#!/usr/bin/env python3
"""IMAP benchmarks, ours against Dovecot 2.4.5 (container `mimap-dovecot`, as the search differential runs it):
- FETCH throughput: `FETCH 1:* (BODY.PEEK[])` of the search differential's 254 messages (mmime's corpus and the
  crafted ones), and `FETCH n (BODY.PEEK[])` of a 1 MB and a 10 MB message, in MB/s of message bytes, over
  plaintext and over TLS (STARTTLS on both);
- SEARCH BODY over those 254 messages: a word most messages have, and one none has (every body read);
- idle connections: N connections (2,000 by default) that each log in, SELECT INBOX and IDLE; the server's RSS at
  0, N/2 and N, and the time from an APPEND by another session until every one of them has seen `* n EXISTS`.

- memory: the server's RSS before, and its peak during, one APPEND and one `FETCH 1 (BODY.PEEK[])` of a 1, 10 and
  50 MB message, over plaintext and TLS, with each command's MB/s (sampled with `ps` every few milliseconds);

    pkgs/mimap/tools/bench.py [--only fetch,memory,search,idle] [--memory-sizes 1,10,50]
                              [--transports plain,tls] [--idle N] [--rounds N]
                              [--no-dovecot]

That one command builds and starts our server through tests/conformance/run.sh (`--imap-bench`, with plaintext
login allowed, larger APPENDs and more connections, and the open-files limit raised). Inside run.sh it is run with
`--ours`. Our RSS is `ps`'s of the server process; Dovecot's is its container's memory as `docker stats` gives it
(a process per IMAP connection; the bench raises its per-user and process limits in tools/dovecot-search.conf). Dovecot is reached through Docker Desktop's port forwarding, which costs it some
throughput and latency that ours does not pay; the load average is printed at the start and end."""
import asyncio, importlib.util, os, pathlib, re, socket, ssl, statistics, subprocess, sys, time

here = pathlib.Path(__file__).resolve().parent
root = here.parent.parent.parent
spec = importlib.util.spec_from_file_location("search_differential", here / "search-differential.py")
differential = importlib.util.module_from_spec(spec)
spec.loader.exec_module(differential)

OURS = ("127.0.0.1", 2143)
OURS_LOGIN = (differential.USER, differential.PASSWORD)
DOVECOT_LOGIN = ("bench", "oracle")
DOVECOT_CONF = here / "dovecot-search.conf"


def load() -> str:
    return " ".join(f"{x:.2f}" for x in os.getloadavg())


# ---- A fast client: buffered reads, literals counted ----

class Fast:
    def __init__(self, address, tls: bool):
        self.sock = socket.create_connection(address, timeout=300)
        self.f = self.sock.makefile("rb", buffering=1 << 20)
        self.n = 0
        self.f.readline()
        if tls:
            self.command("STARTTLS")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.sock = ctx.wrap_socket(self.sock, server_hostname="localhost")
            self.f = self.sock.makefile("rb", buffering=1 << 20)

    def command(self, text, literal: bytes = None) -> tuple:
        """(the literal bytes received, the response lines without literals, the tagged line)."""
        self.n += 1
        tag = b"b%d" % self.n
        if literal is not None:
            self.sock.sendall(tag + b" " + text.encode() + b" {%d+}\r\n" % len(literal))
            self.sock.sendall(literal + b"\r\n")
        else:
            self.sock.sendall(tag + b" " + text.encode() + b"\r\n")
        received, lines = 0, []
        while True:
            line = self.f.readline()
            if not line:
                raise EOFError("connection closed")
            while (m := re.search(rb"\{(\d+)\+?\}\r\n$", line)):
                n = int(m.group(1))
                got = self.f.read(n)
                if len(got) != n:
                    raise EOFError("connection closed")
                received += n
                more = self.f.readline()
                line = line + more
            lines.append(line)
            if line.startswith(tag + b" "):
                if line.split(b" ")[1] != b"OK":
                    raise RuntimeError(f"{text[:60]}: {line[:200]!r}")
                return received, lines, line

    def close(self):
        try:
            self.command("LOGOUT")
        except Exception:
            pass
        self.sock.close()


def big_message(size: int, label: str) -> bytes:
    """A text/plain message of about `size` bytes, lines of 76 characters."""
    head = (f"From: bench@example.org\r\nTo: imap@example.org\r\nSubject: {label}\r\n"
            f"Message-ID: <{label}@bench.test>\r\nDate: Mon, 2 Nov 2026 10:00:00 +0000\r\n"
            f"Content-Type: text/plain; charset=us-ascii\r\n\r\n").encode()
    line = (b"The quick brown fox jumps over the lazy dog 0123456789 abcdefghijklmnopqrstuv\r\n")
    return head + line * ((size - len(head)) // len(line))


def timed(c: Fast, text: str) -> tuple:
    started = time.perf_counter()
    received, lines, _ = c.command(text)
    return time.perf_counter() - started, received, lines


# ---- FETCH and SEARCH ----

def prepare(address, login, items, big: list):
    c = Fast(address, False)
    c.command(f"LOGIN {login[0]} {login[1]}")
    for name in ("bench-corpus", "bench-large"):
        try:
            c.command(f'DELETE "{name}"')
        except RuntimeError:
            pass
        c.command(f'CREATE "{name}"')
    started = time.perf_counter()
    for i, (_, data) in enumerate(items):
        c.command(f'APPEND "bench-corpus" {differential.flags_of(i)} '
                  f'"{differential.imap_date(differential.date_of(i))}"', data)
    corpus_secs = time.perf_counter() - started
    appended = []
    for data in big:
        started = time.perf_counter()
        c.command('APPEND "bench-large" ()', data)
        appended.append(time.perf_counter() - started)
    c.close()
    return corpus_secs, appended


def fetch_bench(label, address, login, rounds: int, sizes: list, pid_rss) -> list:
    rows = []
    for tls in (False, True):
        c = Fast(address, tls)
        c.command(f"LOGIN {login[0]} {login[1]}")
        c.command('EXAMINE "bench-corpus"')
        timed(c, "FETCH 1:* (BODY.PEEK[])")  # warm the caches
        samples = [timed(c, "FETCH 1:* (BODY.PEEK[])") for _ in range(rounds)]
        best = min(s[0] for s in samples)
        rows.append((label, "TLS" if tls else "plain", "corpus (254)", samples[0][1],
                     statistics.median(s[0] for s in samples), samples[0][1] / best / 1e6, None))
        c.command('EXAMINE "bench-large"')
        for k, size in enumerate(sizes, 1):
            timed(c, f"FETCH {k} (BODY.PEEK[])")
            samples = [timed(c, f"FETCH {k} (BODY.PEEK[])") for _ in range(rounds)]
            before, after = None, pid_rss()
            best = min(s[0] for s in samples)
            rows.append((label, "TLS" if tls else "plain", f"{size // 1000000} MB", samples[0][1],
                         statistics.median(s[0] for s in samples), samples[0][1] / best / 1e6, (before, after)))
        c.close()
    return rows


class Peak:
    """The highest of `rss()` while the block runs, sampled every few milliseconds on a thread (and once at the end)."""

    def __init__(self, rss):
        self.rss, self.peak, self.stop = rss, 0, False

    def sample(self):
        while not self.stop:
            self.peak = max(self.peak, self.rss())
            time.sleep(0.003)

    def __enter__(self):
        import threading
        self.thread = threading.Thread(target=self.sample, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stop = True
        self.thread.join()
        self.peak = max(self.peak, self.rss())


def memory_bench(label, address, login, sizes: list, rss, transports: list) -> list:
    """For each transport and size: the server's RSS before, its peak during one APPEND of the message (LITERAL+)
    and during one `FETCH 1 (BODY.PEEK[])` of it, with each command's time. A fresh mailbox each time."""
    rows = []
    for tls in [t == "tls" for t in transports]:
        for size in sizes:
            data = big_message(size, f"mem{size}{'t' if tls else 'p'}{time.time_ns()}")
            c = Fast(address, tls)
            c.command(f"LOGIN {login[0]} {login[1]}")
            try:
                c.command('DELETE "bench-memory"')
            except RuntimeError:
                pass
            c.command('CREATE "bench-memory"')
            before = rss()
            with Peak(rss) as appending:
                started = time.perf_counter()
                c.command('APPEND "bench-memory" ()', data)
                append_secs = time.perf_counter() - started
            c.command('EXAMINE "bench-memory"')
            with Peak(rss) as fetching:
                started = time.perf_counter()
                received, _, _ = c.command("FETCH 1 (BODY.PEEK[])")
                fetch_secs = time.perf_counter() - started
            if received != len(data):
                raise RuntimeError(f"FETCH gave {received} bytes of {len(data)}")
            c.close()
            rows.append((label, "TLS" if tls else "plain", size, before, appending.peak, len(data) / append_secs / 1e6,
                         fetching.peak, len(data) / fetch_secs / 1e6, rss(), load()))
    return rows


SEARCHES = ['BODY "the"', 'BODY "zqxjkvbw"', 'TEXT "message"', 'BODY "fox"']


def search_bench(label, address, login, rounds: int) -> list:
    c = Fast(address, False)
    c.command(f"LOGIN {login[0]} {login[1]}")
    c.command('EXAMINE "bench-corpus"')
    rows = []
    for query in SEARCHES:
        timed(c, f"UID SEARCH {query}")
        samples = []
        for _ in range(rounds):
            secs, _, lines = timed(c, f"UID SEARCH {query}")
            samples.append(secs)
        found = sum(len(x.split()) - 2 for x in lines if x.startswith(b"* SEARCH"))
        rows.append((label, query, found, statistics.median(samples) * 1000, min(samples) * 1000))
    c.close()
    return rows


# ---- Idle connections ----

async def open_idle(address, login, gate) -> tuple:
    async with gate:
        r, w = await asyncio.open_connection(*address, limit=1 << 16)
        await r.readline()
        for tag, text in ((b"a", f"LOGIN {login[0]} {login[1]}"), (b"b", "SELECT INBOX")):
            w.write(tag + b" " + text.encode() + b"\r\n")
            while True:
                line = await r.readline()
                if not line:
                    raise EOFError("closed")
                if line.startswith(tag + b" "):
                    if line.split(b" ")[1] != b"OK":
                        raise RuntimeError(line)
                    break
        w.write(b"c IDLE\r\n")
        while not (line := await r.readline()).startswith(b"+"):
            if not line:
                raise EOFError("closed")
        return r, w


async def wait_exists(r) -> float:
    while True:
        line = await r.readline()
        if not line:
            raise EOFError("closed")
        if line.endswith(b" EXISTS\r\n"):
            return time.perf_counter()


async def idle_bench(label, address, login, n: int, rss) -> dict:
    out = {"label": label, "n": n, "rss": [(0, rss())]}
    gate = asyncio.Semaphore(64)
    conns, failed = [], 0
    started = time.perf_counter()
    for half in (n // 2, n - n // 2):
        results = await asyncio.gather(*[open_idle(address, login, gate) for _ in range(half)],
                                       return_exceptions=True)
        for x in results:
            if isinstance(x, BaseException):
                failed += 1
                if failed <= 3:
                    print(f"  {label}: a connection failed: {x!r}")
            else:
                conns.append(x)
        await asyncio.sleep(2)
        out["rss"].append((len(conns), rss()))
    out["open_secs"] = time.perf_counter() - started
    out["failed"] = failed
    waiters = [asyncio.ensure_future(wait_exists(r)) for r, _ in conns]
    await asyncio.sleep(0.5)
    c = Fast(address, False)
    c.command(f"LOGIN {login[0]} {login[1]}")
    sent = time.perf_counter()
    c.command("APPEND INBOX ()", big_message(2000, f"idle{int(time.time())}"))
    appended = time.perf_counter()
    done, pending = await asyncio.wait(waiters, timeout=120)
    times = sorted(t.result() - sent for t in done if not t.exception())
    out["append_ms"] = (appended - sent) * 1000
    out["seen"] = len(times)
    out["first_ms"] = times[0] * 1000 if times else None
    out["median_ms"] = statistics.median(times) * 1000 if times else None
    out["all_ms"] = times[-1] * 1000 if times else None
    for t in pending:
        t.cancel()
    c.close()
    for _, w in conns:
        w.close()
    await asyncio.sleep(1)
    return out


def our_rss() -> int:
    pid = os.environ.get("SERVER_PID")
    got = subprocess.run(["ps", "-o", "rss=", "-p", pid], capture_output=True, text=True)
    return int(got.stdout.strip() or 0)


def dovecot_rss() -> int:
    """The container's memory as its cgroup counts it (each page once), in KiB: the sum of its processes' RSS would
    count the libraries they share once per process (about 11 MB each)."""
    got = subprocess.run(["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", differential.CONTAINER],
                         capture_output=True, text=True)
    m = re.match(r"([\d.]+)\s*([KMG]i?B)", got.stdout.strip())
    if not m:
        return 0
    scale = {"KiB": 1, "KB": 1, "MiB": 1024, "MB": 1024, "GiB": 1024 * 1024, "GB": 1024 * 1024}[m.group(2)]
    return int(float(m.group(1)) * scale)


def dovecot_limits(n: int):
    """Room for n IMAP processes of one user in the oracle container (its configuration file is shared with the
    differentials; these settings change nothing they test)."""
    text = DOVECOT_CONF.read_text()
    if "mail_max_userip_connections" not in text:
        with open(DOVECOT_CONF, "a") as f:  # appended in place: the container mounts this file
            f.write("# For tools/bench.py's idle connections: a process per IMAP connection, all of one user.\n"
                    "mail_max_userip_connections = 10000\ndefault_client_limit = 10000\n"
                    "service imap {\n  process_limit = 10000\n}\n")
    subprocess.run(["docker", "exec", differential.CONTAINER, "doveadm", "reload"], capture_output=True)
    time.sleep(2)


def mb(kib: int) -> str:
    return f"{kib / 1024:.0f} MB"


def run(args: list) -> int:
    value = lambda name, default: int(args[args.index(name) + 1]) if name in args else default
    only = args[args.index("--only") + 1].split(",") if "--only" in args else ["fetch", "memory", "search", "idle"]
    rounds, idle_n = value("--rounds", 5), value("--idle", 2000)
    memory_sizes = [int(x) * 1_000_000 for x in
                    (args[args.index("--memory-sizes") + 1] if "--memory-sizes" in args else "1,10,50").split(",")]
    # A server's RSS keeps its high-water mark, so each transport is best measured on a fresh server.
    transports = args[args.index("--transports") + 1].split(",") if "--transports" in args else ["plain", "tls"]
    dovecot = "--no-dovecot" not in args
    print(f"load at start: {load()}; open files: {subprocess.run(['sh', '-c', 'ulimit -n'], capture_output=True, text=True).stdout.strip()}")
    if dovecot:
        differential.ensure_dovecot()
    servers = [("ours", OURS, OURS_LOGIN, our_rss)]
    if dovecot:
        servers.append(("dovecot", differential.DOVECOT, DOVECOT_LOGIN, dovecot_rss))
    sizes = [1_000_000, 10_000_000]
    if "fetch" in only or "search" in only:
        items = differential.messages()
        big = [big_message(s, f"large{s}") for s in sizes]
        for label, address, login, _ in servers:
            corpus_secs, appended = prepare(address, login, items, big)
            print(f"{label}: appended the corpus in {corpus_secs:.1f} s; 1 MB in {appended[0] * 1000:.0f} ms, "
                  f"10 MB in {appended[1] * 1000:.0f} ms")
    if "fetch" in only:
        print("FETCH BODY.PEEK[]: server, transport, what, bytes, median s, best MB/s, server RSS after")
        for label, address, login, rss in servers:
            for row in fetch_bench(label, address, login, rounds, sizes, rss):
                extra = f"  server RSS after {mb(row[6][1])}" if row[6] else ""
                print(f"  {row[0]:8} {row[1]:6} {row[2]:13} {row[3]:>10} B  {row[4]:7.3f} s  {row[5]:7.1f} MB/s{extra}")
    if "memory" in only:
        print("memory, one message: server, transport, size, RSS before, peak during APPEND, APPEND MB/s, "
              "peak during FETCH BODY.PEEK[], FETCH MB/s, RSS after")
        for label, address, login, rss in servers:
            for row in memory_bench(label, address, login, memory_sizes, rss, transports):
                print(f"  {row[0]:8} {row[1]:6} {row[2] // 1000000:3} MB  before {mb(row[3]):>7}  "
                      f"APPEND peak {mb(row[4]):>7} {row[5]:7.1f} MB/s  FETCH peak {mb(row[6]):>7} {row[7]:7.1f} MB/s  "
                      f"after {mb(row[8]):>7}  (load {row[9]})")
    if "search" in only:
        print("UID SEARCH over the corpus: server, query, found, median ms, best ms")
        for label, address, login, _ in servers:
            for row in search_bench(label, address, login, rounds):
                print(f"  {row[0]:8} {row[1]:22} {row[2]:4}  {row[3]:8.1f} ms  {row[4]:8.1f} ms")
    if "idle" in only:
        if dovecot:
            dovecot_limits(idle_n)
        for label, address, login, rss in servers:
            out = asyncio.run(idle_bench(label, address, login, idle_n, rss))
            print(f"idle, {label}: {out['n']} connections opened (LOGIN, SELECT, IDLE) in {out['open_secs']:.1f} s, "
                  f"{out['failed']} failed; RSS " + ", ".join(f"{k}: {mb(v)}" for k, v in out["rss"]))
            if out["seen"]:
                print(f"  one APPEND ({out['append_ms']:.1f} ms) seen by {out['seen']} of {out['n'] - out['failed']}: "
                      f"first {out['first_ms']:.1f} ms, median {out['median_ms']:.1f} ms, all {out['all_ms']:.1f} ms")
            else:
                print("  the APPEND was seen by none")
            print(f"  load: {load()}")
    print(f"load at end: {load()}")
    return 0


def main():
    args = sys.argv[1:]
    if "--ours" not in args:
        command = [str(root / "tests" / "conformance" / "run.sh"), "--imap-bench"] + args
        sys.exit(subprocess.run(command).returncode)
    sys.exit(run(args))


if __name__ == "__main__":
    main()
