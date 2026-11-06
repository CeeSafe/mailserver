#!/usr/bin/env python3
"""IMAP command latency: one session logs in once (plaintext) and times many round trips of each command, against
our server and against Dovecot 2.4.5 (container `mimap-dovecot`, as the search differential runs it):
- NOOP; SELECT (the same mailbox again); FETCH 1 (FLAGS); FETCH 1 (BODY.PEEK[]); STORE 1 +FLAGS / -FLAGS (\\Flagged,
  alternately, so each one changes something);
- NOOP after another session's change: a second session toggles a flag on message 2, and the first session's NOOP,
  which must announce it (`* 2 FETCH (FLAGS ...)`), is timed.
The mailbox holds the search differential's 254 messages (mmime's corpus and the crafted ones), so a command that
re-reads the whole mailbox shows.

    pkgs/mimap/tools/latency.py [-n N] [--no-dovecot] [--tls] [--smtp] [--background N]

That one command builds and starts our server through tests/conformance/run.sh (`--imap-latency`, with plaintext
login allowed). Inside run.sh it is run with `--ours`. `--smtp` also times SMTP commands on our server (EHLO, MAIL,
RCPT, RSET, NOOP, and a whole small message), which have no Dovecot counterpart. Each line gives the median, the
99th percentile and the mean in milliseconds.

`--background N` adds N other clients while the commands are timed, each as imaptest's stress mode does: log in,
SELECT, FETCH, STORE, log out, again and again (on our server LOGIN checks bcrypt, about 300 ms of CPU). With
`--steady` they log in once and repeat the rest."""
import importlib.util, os, pathlib, socket, statistics, subprocess, sys, threading, time

here = pathlib.Path(__file__).resolve().parent
root = here.parent.parent.parent
spec = importlib.util.spec_from_file_location("search_differential", here / "search-differential.py")
differential = importlib.util.module_from_spec(spec)
spec.loader.exec_module(differential)

OURS_PLAIN = ("127.0.0.1", 2143)
OURS_TLS = ("127.0.0.1", 2993)
SMTP = ("127.0.0.1", 2587)


def timed(c, text: str) -> float:
    started = time.perf_counter()
    lines = c.command([text.encode()])
    elapsed = time.perf_counter() - started
    assert lines[-1].split(b" ")[1] == b"OK", (text, lines[-1])
    return elapsed * 1000


def summary(samples: list) -> str:
    s = sorted(samples)
    p99 = s[min(len(s) - 1, int(len(s) * 0.99))]
    return f"median {statistics.median(s):7.2f}  p99 {p99:7.2f}  mean {statistics.mean(s):7.2f}"


def measure(label: str, a, b, mailbox: str, n: int) -> dict:
    """The samples of each command, `a` timed and `b` making the other session's changes."""
    out = {}
    a.ok(f'SELECT "{mailbox}"')
    b.ok(f'SELECT "{mailbox}"')
    for _ in range(10):
        timed(a, "NOOP")
    out["NOOP"] = [timed(a, "NOOP") for _ in range(n)]
    out["SELECT"] = [timed(a, f'SELECT "{mailbox}"') for _ in range(n)]
    out["FETCH 1 (FLAGS)"] = [timed(a, "FETCH 1 (FLAGS)") for _ in range(n)]
    out["FETCH 1 (BODY.PEEK[])"] = [timed(a, "FETCH 1 (BODY.PEEK[])") for _ in range(n)]
    out["STORE 1 +FLAGS"] = [timed(a, f"STORE 1 {'+' if k % 2 == 0 else '-'}FLAGS (\\Flagged)") for k in range(n)]
    after = []
    for k in range(n):
        b.ok(f"STORE 2 {'+' if k % 2 == 0 else '-'}FLAGS (\\Answered)")
        started = time.perf_counter()
        lines = a.command([b"NOOP"])
        after.append((time.perf_counter() - started) * 1000)
        assert any(b" FETCH " in x for x in lines), lines
    out["NOOP after a change"] = after
    print(f"{label}:")
    for name, samples in out.items():
        print(f"  {name:24} {summary(samples)}")
    return out


def prepare(c, mailbox: str, items):
    c.command([f'DELETE "{mailbox}"'.encode()])
    c.ok(f'CREATE "{mailbox}"')
    differential.fill(c, mailbox, items)


def smtp_latency(n: int):
    """SMTP on the submission port (STARTTLS is offered but not needed for these): each command's round trip."""
    import ssl
    sock = socket.create_connection(SMTP, timeout=30)
    f = sock.makefile("rb")

    def reply():
        while True:
            line = f.readline()
            if not line:
                raise EOFError
            if line[3:4] != b"-":
                return line

    def timed_smtp(text: str) -> float:
        started = time.perf_counter()
        sock.sendall(text.encode() + b"\r\n")
        line = reply()
        return (time.perf_counter() - started) * 1000, line

    reply()
    out = {"EHLO": [], "NOOP": [], "RSET": []}
    for _ in range(n):
        out["EHLO"].append(timed_smtp("EHLO latency.test")[0])
        out["NOOP"].append(timed_smtp("NOOP")[0])
        out["RSET"].append(timed_smtp("RSET")[0])
    sock.close()
    # MAIL and RCPT need an authenticated session on submission: the MX port takes them for a local recipient.
    sock = socket.create_connection(("127.0.0.1", 2525), timeout=30)
    f = sock.makefile("rb")
    reply()
    timed_smtp("EHLO latency.test")
    out.update({"MAIL (mx)": [], "RCPT (mx)": [], "DATA+message (mx)": []})
    for k in range(n):
        t, line = timed_smtp("MAIL FROM:<sender@example.org>")
        out["MAIL (mx)"].append(t)
        t, line = timed_smtp("RCPT TO:<imap@example.org>")
        out["RCPT (mx)"].append(t)
        assert line.startswith(b"250"), line
        started = time.perf_counter()
        sock.sendall(b"DATA\r\n")
        reply()
        sock.sendall(b"From: sender@example.org\r\nTo: imap@example.org\r\nSubject: latency %d\r\n\r\nbody\r\n.\r\n" % k)
        line = reply()
        out["DATA+message (mx)"].append((time.perf_counter() - started) * 1000)
    sock.close()
    print("smtp, ours:")
    for name, samples in out.items():
        print(f"  {name:24} {summary(samples)}")


class Background:
    """N clients logging in, working and logging out in a loop until stopped; how many cycles they did."""
    def __init__(self, n: int, address, tls: bool, login: str, mailbox: str, steady: bool):
        self.stop, self.cycles, self.errors, self.steady = threading.Event(), 0, 0, steady
        self.started = time.time()
        self.threads = [threading.Thread(target=self.loop, args=(address, tls, login, mailbox), daemon=True)
                        for _ in range(n)]
        for t in self.threads:
            t.start()

    def loop(self, address, tls, login, mailbox):
        while not self.stop.is_set():
            try:
                c = differential.Client(address, tls)
                c.ok(login)
                while True:
                    c.ok(f'SELECT "{mailbox}"')
                    c.ok("FETCH 1:20 (FLAGS UID)")
                    c.ok("FETCH 3 (BODY.PEEK[])")
                    c.ok("STORE 4 +FLAGS (\\Seen)")
                    self.cycles += 1
                    if not self.steady or self.stop.is_set():
                        break
                c.ok("LOGOUT")
                c.sock.close()
            except Exception:
                self.errors += 1
                time.sleep(0.1)

    def finish(self) -> str:
        self.stop.set()
        for t in self.threads:
            t.join()
        secs = time.time() - self.started
        return (f"{len(self.threads)} background clients: {self.cycles} cycles in {secs:.1f} s "
                f"({self.cycles / secs:.1f}/s), {self.errors} errors")


def run(args: list) -> int:
    n = int(args[args.index("-n") + 1]) if "-n" in args else 200
    tls = "--tls" in args
    print(f"load: {os.getloadavg()[0]:.2f} {os.getloadavg()[1]:.2f} {os.getloadavg()[2]:.2f}; {n} each")
    items = differential.messages()
    ours = [differential.Client(OURS_TLS if tls else OURS_PLAIN, tls) for _ in range(2)]
    for c in ours:
        c.ok(f"LOGIN {differential.USER} {differential.PASSWORD}")
    background = int(args[args.index("--background") + 1]) if "--background" in args else 0
    prepare(ours[0], "latency", items)
    noise = Background(background, OURS_TLS if tls else OURS_PLAIN, tls,
                       f"LOGIN {differential.USER} {differential.PASSWORD}", "latency", "--steady" in args) if background else None
    measure("ours" + (" (TLS)" if tls else "") + (f", {background} background clients" if background else ""),
            ours[0], ours[1], "latency", n)
    if noise:
        print("  " + noise.finish())
    if "--no-dovecot" not in args:
        differential.ensure_dovecot()
        theirs = [differential.Client(differential.DOVECOT, False) for _ in range(2)]
        for c in theirs:
            c.ok("LOGIN oracle oracle")
        prepare(theirs[0], "latency", items)
        noise = Background(background, differential.DOVECOT, False, "LOGIN oracle oracle", "latency", "--steady" in args) \
            if background else None
        measure("dovecot" + (f", {background} background clients" if background else ""), theirs[0], theirs[1],
                "latency", n)
        if noise:
            print("  " + noise.finish())
    if "--smtp" in args:
        smtp_latency(n)
    print(f"load: {os.getloadavg()[0]:.2f} {os.getloadavg()[1]:.2f} {os.getloadavg()[2]:.2f}")
    return 0


def main():
    args = sys.argv[1:]
    if "--ours" not in args:
        command = [str(root / "tests" / "conformance" / "run.sh"), "--imap-latency"] + args
        sys.exit(subprocess.run(command).returncode)
    sys.exit(run(args))


if __name__ == "__main__":
    main()
