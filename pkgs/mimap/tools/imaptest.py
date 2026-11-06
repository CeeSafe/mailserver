#!/usr/bin/env python3
"""Dovecot's imaptest (https://imapwiki.org/ImapTest) against our server, with Dovecot 2.4.5 as the reference.

    pkgs/mimap/tools/imaptest.py [--no-dovecot] [--no-compliance] [--no-stress] [--secs N] [--clients N]
        [--set imaptest-setting=value ...] [-v]

That one command builds and starts our server through tests/conformance/run.sh (`--imaptest`, with plaintext
login allowed), and then runs, in Docker (image dovecot/imaptest):
- the scripted compliance tests (the `src/tests` directory of imaptest's source at IMAPTEST_COMMIT, fetched once into
  pkgs/mimap/out/imaptest) against our server, and against Dovecot (container `mimap-dovecot`, as the search
  differential starts it) as the reference;
- the stress mode: `clients` concurrent clients sending random commands for `secs` seconds to one mailbox, with
  imaptest's state tracking, which reports any response that contradicts what the server said before (flags, UIDs,
  EXPUNGE, FETCH bodies), against both. It appends messages from mmime's corpus (pkgs/mmime/tests/corpus).

Every failing compliance command must be listed in tests/imaptest-deviations.txt with its reason, or the run fails;
a listed one that passes fails it too. Any `Error:` from imaptest (a protocol inconsistency) fails it. `-v` prints
imaptest's whole output. Inside run.sh it is run with `--ours`."""
import importlib.util, os, pathlib, platform, re, subprocess, sys, tarfile, tempfile, time, urllib.request

here = pathlib.Path(__file__).resolve().parent
package = here.parent
root = package.parent.parent
corpus = package.parent / "mmime" / "tests" / "corpus"
deviations_file = package / "tests" / "imaptest-deviations.txt"
IMAGE = "dovecot/imaptest"
IMAPTEST_COMMIT = "d66226a339882b814130ca6b4fe2a12db4d631f8"
cache = package / "out" / "imaptest"
OURS_PORT = 2143
USERS = ("imaptest1@example.org", "imaptest2@example.org")
PASSWORD = "imaptest-pw"

# The search differential's Dovecot container and client.
spec = importlib.util.spec_from_file_location("search_differential", here / "search-differential.py")
differential = importlib.util.module_from_spec(spec)
spec.loader.exec_module(differential)


def tests_dir() -> pathlib.Path:
    """imaptest's scripted tests at IMAPTEST_COMMIT (they are not in the Docker image)."""
    target = cache / IMAPTEST_COMMIT / "tests"
    if target.is_dir():
        return target
    url = f"https://github.com/dovecot/imaptest/archive/{IMAPTEST_COMMIT}.tar.gz"
    with tempfile.TemporaryDirectory() as tmp:
        archive = pathlib.Path(tmp) / "imaptest.tar.gz"
        urllib.request.urlretrieve(url, archive)
        prefix = f"imaptest-{IMAPTEST_COMMIT}/src/tests/"
        target.mkdir(parents=True)
        with tarfile.open(archive) as tar:
            for member in tar.getmembers():
                if member.isfile() and member.name.startswith(prefix) and "/" not in member.name[len(prefix):]:
                    (target / member.name[len(prefix):]).write_bytes(tar.extractfile(member).read())
    return target


def stress_mbox() -> pathlib.Path:
    """mmime's corpus as an mbox, the messages the stress mode appends. imaptest takes a Message-ID to name one
    message, and checks that every FETCH of it agrees: the corpus reuses Message-IDs (MimeKit's tests), so each message
    gets its own; and messages imaptest itself cannot track are left out (a NUL, no header end, a header over 16 KiB,
    which its HEADER.FIELDS check misreads), whichever server it runs against."""
    path = cache / "corpus.mbox"
    if path.exists():
        return path
    cache.mkdir(parents=True, exist_ok=True)
    out = bytearray()
    for n, f in enumerate(sorted(corpus.glob("*.eml"))):
        data = f.read_bytes().replace(b"\r\n", b"\n")
        end = data.find(b"\n\n")
        if b"\0" in data or b"\r" in data or end < 0 or end > 16384:
            continue
        header = re.sub(rb"(?im)^message-id:.*\n(?:[ \t].*\n)*", b"", data[: end + 1])
        data = b"Message-ID: <corpus-%d@mimap.test>\n" % n + header + data[end + 1:]
        out += b"From imaptest@example.org  Fri Feb 22 17:06:23 2008\n"
        for line in data.split(b"\n"):
            out += (b">" + line if re.match(rb">*From ", line) else line) + b"\n"
        if not data.endswith(b"\n"):
            out += b"\n"
    path.write_bytes(bytes(out))
    return path


def docker_host() -> tuple:
    """How a container reaches the host's 127.0.0.1: host networking on Linux, else Docker Desktop's host."""
    if platform.system() == "Linux":
        return ["--network", "host"], "127.0.0.1"
    got = subprocess.run(["docker", "run", "--rm", "--entrypoint", "getent", IMAGE, "ahostsv4",
                          "host.docker.internal"], capture_output=True, text=True)
    return [], got.stdout.split()[0] if got.stdout.split() else "host.docker.internal"


def imaptest(args: list, volumes: dict, timeout: int) -> str:
    network, host = docker_host()
    command = ["docker", "run", "--rm"] + network
    for source, target in volumes.items():
        command += ["-v", f"{source}:{target}:ro"]
    command += [IMAGE, f"host={host}"] + args
    done = subprocess.run(command, capture_output=True, timeout=timeout)
    return (done.stdout + done.stderr).decode("utf-8", "replace")


def compliance(label: str, port: int, users: tuple, password: str, verbose: bool) -> tuple:
    """The scripted tests: the failing commands as `group n/m`, the `Error:` lines, and imaptest's summary."""
    output = imaptest([f"port={port}", f"user={users[0]}", f"user2={users[1]}", f"pass={password}", "test=/tests"],
                      {tests_dir(): "/tests"}, 900)
    if verbose:
        print(output)
    failed = sorted(set(re.findall(r"^\*\*\* Test (.+? command \d+/\d+) \(line \d+\)", output, re.M)))
    errors = [x for x in output.splitlines() if x.startswith(("Error:", "Panic:", "Fatal:"))]
    summary = [x for x in output.splitlines() if re.match(r"\d+ test groups:|base protocol:|extensions:", x)]
    print(f"compliance, {label}: " + "; ".join(summary))
    return failed, errors, summary


def stress(label: str, port: int, user: str, password: str, secs: int, clients: int, verbose: bool,
           extra: list) -> list:
    """The stress mode: imaptest's last totals line, and its `Error:` lines. `extra` are more imaptest settings
    (`logout=0`: the clients stay logged in)."""
    mbox = stress_mbox()
    output = imaptest([f"port={port}", f"user={user}", f"pass={password}", "mbox=/mbox/corpus.mbox",
                       f"secs={secs}", f"clients={clients}"] + extra, {mbox.parent: "/mbox"}, secs + 300)
    if verbose:
        print(output)
    lines = output.splitlines()
    errors = [x for x in lines if x.startswith(("Error:", "Panic:", "Fatal:"))]
    # The totals: after `Totals:`, a line of command names, two of percentages, then the counts of the whole run.
    at = next((k for k in range(len(lines)) if lines[k].startswith("Totals:")), len(lines))
    names = lines[at + 1].split() if at + 1 < len(lines) else []
    counts = next((x.split() for x in lines[at + 2:] if x.split() and x.split()[0].isdigit()), [])
    per = dict(zip(names, counts))
    total = sum(int(c) for c in counts[: len(names)] if c.isdigit())
    print(f"stress, {label}: {clients} clients, {secs} s{''.join(' ' + x for x in extra)}: {total} commands "
          f"({total / secs:.0f}/s), {len(errors)} errors")
    print("    " + "  ".join(f"{n} {per.get(n, '?')}" for n in names))
    # The milliseconds per command: the last `ms/cmd avg` line imaptest printed while commands ran (the lines
    # cover each ten-second period).
    avg = [x.split() for x in lines if x.rstrip().endswith("ms/cmd avg") and any(v != "0" for v in x.split()[:-2])]
    if avg:
        print("    ms/cmd: " + "  ".join(f"{n} {v}" for n, v in zip(names, avg[-1])))
    # The errors by kind: imaptest's message without the client and the response it quotes.
    kinds = {}
    for e in errors:
        kind = re.sub(r"^Error: [^:]*: (uid=\d+ [^:]*: )?", "", e).split(":")[0][:80]
        kinds[kind] = kinds.get(kind, 0) + 1
    for kind, n in sorted(kinds.items(), key=lambda x: -x[1]):
        print(f"    {n:4} {kind}")
    return errors


def load_deviations() -> tuple:
    listed, tags = {}, {}
    for raw in deviations_file.read_text().splitlines():
        if not raw.strip() or raw.startswith("#"):
            continue
        if raw.startswith("= "):
            tag, reason = raw[2:].split(":", 1)
            tags[tag.strip()] = reason.strip()
            continue
        test, tag = [x.strip() for x in raw.split(" | ")]
        listed[test] = tag
    for test, tag in listed.items():
        if tag not in tags:
            sys.exit(f"{deviations_file.name}: undefined tag {tag!r} for {test}")
    return listed, tags


def add_users():
    for user in USERS:
        subprocess.run([os.environ["MAILSERVER_BIN"], "--config", os.environ["MAILSERVER_CONFIG"], "add-user", user,
                        PASSWORD], check=True, capture_output=True)


def check_compliance(verbose: bool, dovecot: bool) -> int:
    """The scripted tests against ours, every failure explained, and against Dovecot for reference."""
    status = 0
    failed, errors, _ = compliance("ours", OURS_PORT, USERS, PASSWORD, verbose)
    listed, tags = load_deviations()
    by_tag = {}
    for test in failed:
        tag = listed.get(test)
        if tag:
            by_tag[tag] = by_tag.get(tag, 0) + 1
        else:
            print(f"  UNEXPLAINED failure: {test}")
            status = 1
    for test in sorted(set(listed) - set(failed)):
        print(f"  listed but passes: {test}")
        status = 1
    for e in errors:
        print(f"  {e}")
        status = 1
    for tag in sorted(by_tag, key=lambda t: -by_tag[t]):
        print(f"  {by_tag[tag]:4} {tag}: {tags[tag]}")
    if dovecot:
        theirs, _, _ = compliance("dovecot", differential.DOVECOT[1], ("itest1", "itest2"), "oracle", verbose)
        for test in theirs:
            print(f"  dovecot fails: {test}")
    return status


def run(args: list) -> int:
    verbose = "-v" in args
    value = lambda name, default: int(args[args.index(name) + 1]) if name in args else default
    secs, clients = value("--secs", 60), value("--clients", 10)
    extra = [args[k + 1] for k in range(len(args) - 1) if args[k] == "--set"]
    if subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True).returncode != 0:
        subprocess.run(["docker", "pull", IMAGE], check=True, capture_output=True)
    add_users()
    status = 0
    dovecot = "--no-dovecot" not in args
    if dovecot:
        differential.ensure_dovecot()
    if "--no-compliance" not in args:
        status |= check_compliance(verbose, dovecot)
    if "--no-stress" not in args:
        status |= 1 if stress("ours", OURS_PORT, USERS[0], PASSWORD, secs, clients, verbose, extra) else 0
        if dovecot:
            # A new user each run: Dovecot's mailboxes stay in the container.
            stress("dovecot", differential.DOVECOT[1], f"stress{int(time.time())}", "oracle", secs, clients, verbose,
                   extra)
    return status


def main():
    args = sys.argv[1:]
    if "--ours" not in args:
        command = [str(root / "tests" / "conformance" / "run.sh"), "--imaptest"] + args
        env = dict(os.environ, IMAP_PLAINTEXT_AUTH="true")
        sys.exit(subprocess.run(command, env=env).returncode)
    sys.exit(run(args))


if __name__ == "__main__":
    main()
