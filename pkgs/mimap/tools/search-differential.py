#!/usr/bin/env python3
"""The SEARCH differential: the same messages, with the same flags, keywords and internal dates, are appended to a
mailbox on our server and on Dovecot 2.4.5, then a battery of UID SEARCH queries runs on both, and the results are
compared by APPEND order. Messages are mmime's corpus (pkgs/mmime/tests/corpus, 244 messages from MimeKit's test
data; `pkgs/mmime/tools/fetch-corpus.py` fetches it) and the crafted ones below.

    pkgs/mimap/tools/search-differential.py [-v]

That one command builds and starts our server through tests/conformance/run.sh (`--search-differential`), and
Dovecot in Docker (container `mimap-dovecot`, image dovecot/dovecot:2.4.5, port 51144, with
tools/dovecot-search.conf: no full-text index, so Dovecot searches by substring as RFC 3501 says). Inside run.sh it
is run with `--ours`.

Every difference must be listed in tests/search-deviations.txt with its reason, or the run fails. A line there is
`query | message | tag`, and `= tag: reason` defines a tag. A listed difference that no longer occurs fails the run
too. `-v` prints each query's counts and explained differences; `--query Q` (repeatable) runs only those queries,
and `--show NAME,NAME` prints which of those messages each side found."""
import base64, datetime, os, pathlib, re, socket, ssl, subprocess, sys, time

here = pathlib.Path(__file__).resolve().parent
package = here.parent
root = package.parent.parent
corpus = package.parent / "mmime" / "tests" / "corpus"
deviations_file = package / "tests" / "search-deviations.txt"
DOVECOT = ("127.0.0.1", 51144)
OURS = ("127.0.0.1", 2993)
CONTAINER = "mimap-dovecot"
USER, PASSWORD = "imap@example.org", "imap-pw"


# ---- Messages ----

def crlf(text: str) -> bytes:
    return text.replace("\n", "\r\n").encode("utf-8")


def b64(data: bytes) -> str:
    return base64.encodebytes(data).decode("ascii")


CRAFTED = {
    "crafted-html-utf8": crlf(
        "From: Web Shop <shop@crafted.test>\nTo: Customer <customer@crafted.test>\nSubject: Your order\n"
        "Date: Mon, 3 Feb 2020 10:00:00 +0100\nMIME-Version: 1.0\nContent-Type: text/html; charset=utf-8\n\n"
        "<html><head><style>.hidden { color: zebra-stripes; }</style></head>\n"
        "<body><p>Your <b>order</b> of crème brûlée has shipped.</p>\n"
        "<p>Tom &amp; Jerry &lt;tracking&gt; caf&#233; &#x263A;</p></body></html>\n"),
    "crafted-base64-latin1": crlf(
        "From: =?ISO-8859-1?Q?Fran=E7ois?= <francois@crafted.test>\nTo: team@crafted.test\n"
        "Subject: Rapport mensuel\nDate: Tue, 4 Feb 2020 23:30:00 -0800\nMIME-Version: 1.0\n"
        "Content-Type: text/plain; charset=ISO-8859-1\nContent-Transfer-Encoding: base64\n\n"
        + b64("Le résumé du mois: été très chaud à Montréal.\r\n"
              "Naïve façade.\r\n".encode("latin-1"))),
    "crafted-qp-latin1": crlf(
        "From: Hans <hans@crafted.test>\nTo: Grete <grete@crafted.test>\nCc: Fritz <fritz@crafted.test>\n"
        "Subject: =?ISO-8859-1?Q?Gr=FC=DFe_aus_K=F6ln?=\nDate: Wed, 05 Feb 2020 08:15:00 +0100\nMIME-Version: 1.0\n"
        "Content-Type: text/plain; charset=iso-8859-1\nContent-Transfer-Encoding: quoted-printable\n\n"
        "Sch=F6ne Gr=FC=DFe aus K=F6ln. Die Stra=DFe ist sehr lang, und das ist ein sehr lan=\n"
        "ges Wort am Zeilenende.   \nM=FCnchen=20\n"),
    "crafted-encoded-subjects": crlf(
        "From: =?UTF-8?B?w4lsb2RpZQ==?= <elodie@crafted.test>\nTo: =?utf-8?q?J=C3=BCrgen?= <juergen@crafted.test>\n"
        "Subject: =?UTF-8?B?w4l0w6kg?= =?ISO-8859-1?Q?=E0_Paris?= and more\n"
        "Date: Thu, 06 Feb 2020 12:00:00 +0000\nMIME-Version: 1.0\nContent-Type: text/plain; charset=us-ascii\n\n"
        "Plain words only.\n"),
    "crafted-no-date": crlf(
        "From: Nobody <nobody@crafted.test>\nTo: someone@crafted.test\nSubject: Undated message\n\n"
        "This message has no Date header at all.\n"),
    "crafted-bad-date": crlf(
        "From: Broken <broken@crafted.test>\nTo: someone@crafted.test\nSubject: Badly dated\nDate: sometime soon\n\n"
        "The Date header cannot be read.\n"),
    "crafted-obsolete-date": crlf(
        "From: Old <old@crafted.test>\nTo: someone@crafted.test\nSubject: Obsolete date\n"
        "Date: Fri, 7 Feb 20 23:59 EST\n\nAn obsolete date with a two-digit year and a zone name.\n"),
    "crafted-alternative": crlf(
        "From: News <news@crafted.test>\nTo: reader@crafted.test\nSubject: Newsletter\n"
        "Date: Sat, 08 Feb 2020 07:00:00 +0000\nMIME-Version: 1.0\n"
        "Content-Type: multipart/alternative; boundary=\"alt\"\n\n--alt\nContent-Type: text/plain; charset=utf-8\n\n"
        "Plain version: unsubscribe here.\n--alt\nContent-Type: text/html; charset=utf-8\n\n"
        "<div>HTML version: <a href=\"https://crafted.test/u\">unsubscribe</a> &nbsp;now</div>\n--alt--\n"),
    "crafted-attached-message": crlf(
        "From: Forwarder <fwd@crafted.test>\nTo: boss@crafted.test\nSubject: Fwd: the contract\n"
        "Date: Sun, 09 Feb 2020 18:00:00 +0200\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"m\"\n\n"
        "--m\nContent-Type: text/plain\n\nSee the attached message.\n--m\nContent-Type: message/rfc822\n\n"
        "From: Lawyer <lawyer@firm.test>\nTo: fwd@crafted.test\nSubject: Contract draft seven\n"
        "Date: Sat, 08 Feb 2020 09:00:00 +0000\n\nPlease sign the indemnity clause.\n--m\n"
        "Content-Type: application/pdf\nContent-Transfer-Encoding: base64\n\n"
        + b64(b"%PDF-1.4 secretpdfword\n") + "--m--\n"),
    "crafted-folded-headers": crlf(
        "From: Many <many@crafted.test>\nTo: one@crafted.test,\n two@crafted.test,\n\tthree@crafted.test\n"
        "Bcc: hidden@crafted.test\nSubject: A subject that is\n folded over two lines\nX-Tracking-Id: ABC-123-xyz\n"
        "Date: Mon, 10 Feb 2020 00:30:00 +1300\n\nFolded headers.\n"),
}


def messages() -> list:
    """(name, bytes), the corpus in name order, then the crafted ones."""
    files = sorted(corpus.glob("*.eml"))
    if not files:
        sys.exit(f"no corpus in {corpus}: run pkgs/mmime/tools/fetch-corpus.py")
    return [(f.stem, f.read_bytes()) for f in files] + list(CRAFTED.items())


ZONES = [0, -5 * 60, 9 * 60 + 30, -11 * 60, 14 * 60]
START = datetime.datetime(2019, 1, 1, tzinfo=datetime.timezone.utc)


def flags_of(i: int) -> str:
    flags = []
    for bit, name in [(2, r"\Seen"), (3, r"\Answered"), (5, r"\Flagged"), (7, r"\Deleted"), (11, r"\Draft")]:
        if i % bit == 0:
            flags.append(name)
    for mod, rest, name in [(4, 1, "$Work"), (6, 2, "Later"), (9, 3, "$Label1")]:
        if i % mod == rest:
            flags.append(name)
    return "(" + " ".join(flags) + ")"


def date_of(i: int) -> datetime.datetime:
    """The internal date: every 3 days and a bit, in one of five zones."""
    utc = START + datetime.timedelta(days=3 * i, seconds=(i * 7919) % 86400)
    zone = datetime.timezone(datetime.timedelta(minutes=ZONES[i % len(ZONES)]))
    return utc.astimezone(zone)


def imap_date(d: datetime.datetime) -> str:
    return d.strftime("%d-%b-%Y %H:%M:%S %z")


# ---- A small IMAP client: literals, and SEARCH's response ----

class Client:
    def __init__(self, address, tls: bool):
        sock = socket.create_connection(address, timeout=120)
        if tls:
            ctx = ssl.create_default_context(cafile=os.environ["CA"])
            ctx.check_hostname = False
            sock = ctx.wrap_socket(sock, server_hostname="localhost")
        self.sock, self.buf, self.n = sock, b"", 0
        self.line()

    def line(self) -> bytes:
        while b"\r\n" not in self.buf:
            chunk = self.sock.recv(1 << 16)
            if not chunk:
                raise EOFError("connection closed")
            self.buf += chunk
        i = self.buf.index(b"\r\n") + 2
        out, self.buf = self.buf[:i], self.buf[i:]
        return out

    def command(self, pieces) -> list:
        """`pieces` are bytes, or ("literal", bytes); synchronizing literals wait for `+`."""
        self.n += 1
        tag = b"t%d" % self.n
        out = tag + b" "
        for p in pieces:
            if isinstance(p, tuple):
                self.sock.sendall(out + b"{%d}\r\n" % len(p[1]))
                while not (resp := self.line()).startswith(b"+"):
                    if resp.startswith(tag + b" "):
                        return [resp]
                out = p[1]
            else:
                out += p
        self.sock.sendall(out + b"\r\n")
        lines = []
        while True:
            resp = self.line()
            lines.append(resp)
            if resp.startswith(tag + b" "):
                return lines

    def ok(self, text: str) -> list:
        lines = self.command([text.encode()])
        assert lines[-1].split(b" ")[1] == b"OK", lines
        return lines


def wire(query: str) -> list:
    """A query as pieces: `{{text}}` becomes a literal (UTF-8), the rest goes as is."""
    pieces = []
    for k, part in enumerate(re.split(r"\{\{(.*?)\}\}", query)):
        if k % 2:
            pieces.append(("literal", part.encode()))
        elif part:
            pieces.append(part.encode())
    return pieces


def uid_search(c: Client, query: str):
    """The UIDs, or the tagged response when it is not OK."""
    lines = c.command([b"UID SEARCH "] + wire(query))
    if lines[-1].split(b" ")[1] != b"OK":
        return lines[-1].strip().decode(errors="replace")
    found = [x for x in lines if x.startswith(b"* SEARCH")]
    return set(int(n) for n in found[0][8:].split()) if found else set()


# ---- Queries ----

def queries(items) -> list:
    """At least one query for every key, alone and combined. Dates are chosen to hit the messages' dates."""
    d = [date_of(i).astimezone(datetime.timezone.utc) for i in range(len(items))]
    day = lambda x: x.strftime("%-d-%b-%Y")
    mid = d[len(d) // 2]
    return [
        # Flags.
        "ALL", "ANSWERED", "UNANSWERED", "DELETED", "UNDELETED", "DRAFT", "UNDRAFT", "FLAGGED", "UNFLAGGED", "SEEN",
        "UNSEEN", "NEW", "OLD", "RECENT", "NOT RECENT",
        "KEYWORD $Work", "KEYWORD later", "KEYWORD $Label1", "UNKEYWORD $Work", "KEYWORD $Missing",
        # Internal dates (UTC: the container's zone and ours).
        f"BEFORE {day(mid)}", f"ON {day(mid)}", f"SINCE {day(mid)}", f"ON {day(d[7])}", f'ON "{day(d[100])}"',
        f"SINCE {day(d[-1])}", "BEFORE 1-Jan-2019",
        # Sent dates: the Date header in its own zone; none or unreadable is 1 January 1970.
        "SENTBEFORE 1-Jan-2000", "SENTSINCE 1-Jan-2005", "SENTON 1-Jan-1970", "SENTBEFORE 2-Jan-1970",
        "SENTON 4-Feb-2020", "SENTON 5-Feb-2020", "SENTON 7-Feb-2020", "SENTON 8-Feb-2020", "SENTON 9-Feb-2020",
        "SENTON 10-Feb-2020", "SENTSINCE 1-Jan-2020 SENTBEFORE 1-Mar-2020",
        # Sizes.
        "LARGER 5000", "SMALLER 1000", "LARGER 0", "SMALLER 4294967295", "LARGER 100000 SMALLER 2000000",
        # Address and other header fields.
        "FROM jwz", "FROM \"@\"", "FROM example",
        # Dovecot's FROM searches its re-written address list; HEADER From its text, as our FROM does.
        "HEADER From \"@\"", "FROM MISSING_DOMAIN", "(HEADER From a HEADER To b)", "FROM {{François}}", "FROM {{ÉLODIE}}", "TO {{jürgen}}",
        "TO \"\"", "CC \"\"", "CC fritz", "BCC \"\"", "BCC hidden", "TO three@crafted",
        "SUBJECT \"\"", "SUBJECT test", "SUBJECT \"=?\"", "SUBJECT {{été à paris}}",
        "SUBJECT {{grüße}}", "SUBJECT \"is folded\"", "SUBJECT \"is  folded\"",
        "HEADER Content-Type multipart", "HEADER Message-ID \"\"", "HEADER X-Mailer \"\"", "HEADER Received \"\"",
        "HEADER X-Tracking-Id abc-123", "HEADER Content-Transfer-Encoding base64", "HEADER mime-version 1.0",
        # Body and text.
        "BODY the", "BODY hello", "BODY boundary", "BODY {{crème brûlée}}", "BODY {{résumé}}",
        "BODY {{Montréal}}", "BODY {{STRAßE}}", "BODY \"langes Wort\"", "BODY {{München}}",
        "BODY indemnity", "BODY \"Contract draft\"", "BODY secretpdfword", "BODY zebra", "BODY \"<b>\"",
        "BODY \"Tom & Jerry\"", "BODY \"&amp;\"", "BODY unsubscribe", "BODY \"nbsp\"", "BODY {{café}}",
        "BODY {{☺}}", "BODY \"Plain words\"", "BODY Content-Type", "BODY X-Mailer",
        "TEXT \"Content-Type\"", "TEXT \"MIME-Version\"", "TEXT jwz", "TEXT indemnity", "TEXT {{Été}}",
        "TEXT \"Subject: Contract\"", "TEXT secretpdfword",
        # Sets.
        "UID 1:50", "UID 100:*", "UID *", "1,5,9:12", "200:*", "*", "9999", "250:9999", "UID 9999",
        # Both refuse: a system flag is not a keyword.
        "KEYWORD \\Seen",
        # Combinations.
        "NOT SEEN", "NOT NOT SEEN", "OR SEEN FLAGGED", "OR (SEEN DRAFT) (NOT FLAGGED LARGER 2000)",
        "NOT (OR BODY the SUBJECT test)", "(FROM a TO b)", "OR OR DELETED DRAFT KEYWORD $Work",
        f"SEEN SINCE {day(mid)} NOT BODY the", "OR SUBJECT test (UNSEEN BODY hello)",
        "UNDELETED (OR FROM jwz (TEXT boundary NOT LARGER 3000))", "NOT (FLAGGED (OR UNSEEN ANSWERED))",
        "CHARSET UTF-8 BODY {{été}}", "CHARSET US-ASCII SUBJECT re",
    ]


# ---- Running ----

def ensure_dovecot():
    state = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER], capture_output=True, text=True)
    if state.stdout.strip() != "true":
        subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True)
        subprocess.run(["docker", "run", "-d", "--name", CONTAINER, "-e", "USER_PASSWORD=oracle", "-p",
                        f"{DOVECOT[0]}:{DOVECOT[1]}:31143", "-v",
                        f"{here / 'dovecot-search.conf'}:/etc/dovecot/conf.d/search.conf:ro",
                        "dovecot/dovecot:2.4.5"], check=True, capture_output=True)
    for _ in range(100):
        try:
            Client(DOVECOT, False).sock.close()
            return
        except OSError:
            time.sleep(0.2)
    sys.exit("Dovecot did not start")


def quoted(name: str) -> str:
    return '"' + name + '"'


def fill(c: Client, mailbox: str, items) -> list:
    """Appends every message to `mailbox`: its UID per message, or None when refused."""
    uids = []
    for i, (name, data) in enumerate(items):
        lines = c.command([f"APPEND {quoted(mailbox)} {flags_of(i)} \"{imap_date(date_of(i))}\" ".encode(),
                           ("literal", data)])
        m = re.search(rb"APPENDUID \d+ (\d+)", lines[-1])
        uids.append(int(m.group(1)) if m and lines[-1].split(b" ")[1] == b"OK" else None)
    # Dovecot gives \Recent to the first session to select the mailbox; take it here, so neither server has any.
    c.ok(f"SELECT {quoted(mailbox)}")
    c.ok("UNSELECT")
    return uids


def load_deviations():
    """The listed differences, {(query, message): tag}, and the tags' reasons."""
    listed, tags = {}, {}
    for raw in deviations_file.read_text().splitlines():
        if not raw.strip() or raw.startswith("#"):
            continue
        if raw.startswith("= "):
            tag, reason = raw[2:].split(":", 1)
            tags[tag.strip()] = reason.strip()
            continue
        query, message, tag = [x.strip() for x in raw.split(" | ")]
        listed[(query, message)] = tag
    for key, tag in listed.items():
        if tag not in tags:
            sys.exit(f"{deviations_file.name}: undefined tag {tag!r} for {key}")
    return listed, tags


def run(verbose: bool, only: list, show: list):
    ensure_dovecot()
    items = messages()
    dovecot = Client(DOVECOT, False)
    dovecot.ok("LOGIN oracle oracle")
    dovecot.command([b'DELETE "searchdiff"'])
    dovecot.ok('CREATE "searchdiff"')
    ours = Client(OURS, True)
    ours.ok(f"LOGIN {USER} {PASSWORD}")
    mailbox = f"searchdiff{int(time.time())}"
    ours.ok(f"CREATE {quoted(mailbox)}")
    started = time.time()
    their_uids, our_uids = fill(dovecot, "searchdiff", items), fill(ours, mailbox, items)
    print(f"appended {len(items)} messages to each in {time.time() - started:.1f} s")
    both = [i for i in range(len(items)) if their_uids[i] is not None and our_uids[i] is not None]
    for i in range(len(items)):
        if i not in both:
            print(f"  not compared: {items[i][0]} (dovecot {their_uids[i]}, ours {our_uids[i]})")
    their_index = {their_uids[i]: i for i in both}
    our_index = {our_uids[i]: i for i in both}
    dovecot.ok('EXAMINE "searchdiff"')
    ours.ok(f"EXAMINE {quoted(mailbox)}")
    deviations, tags = load_deviations()
    used, by_tag = set(), {}
    total = matches = explained_count = unexplained = 0
    qs = only or queries(items)
    timings = []
    for query in qs:
        theirs = uid_search(dovecot, query)
        t0 = time.time()
        mine = uid_search(ours, query)
        timings.append((time.time() - t0, query))
        if isinstance(theirs, str) or isinstance(mine, str):
            same = isinstance(theirs, str) and isinstance(mine, str)
            print(f"{'  ' if same else 'X '}{query}: dovecot {theirs!r}, ours {mine!r}")
            unexplained += 0 if same else 1
            continue
        a = {their_index[u] for u in theirs if u in their_index}
        b = {our_index[u] for u in mine if u in our_index}
        total += len(both)
        matches += len(a | b)
        diff = sorted(a ^ b)
        lines = []
        for i in diff:
            name = items[i][0]
            side = "only dovecot" if i in a else "only ours"
            tag = deviations.get((query, name))
            if tag:
                explained_count += 1
                used.add((query, name))
                by_tag[tag] = by_tag.get(tag, 0) + 1
                if verbose:
                    lines.append(f"    {side}: {name} ({tag})")
            else:
                unexplained += 1
                lines.append(f"    UNEXPLAINED {side}: {name}")
        if show:
            names = lambda found: [items[i][0] for i in sorted(found) if items[i][0] in show]
            print(f"{query}: dovecot {names(a)}, ours {names(b)}")
        if verbose or any("UNEXPLAINED" in x for x in lines):
            print(f"{query}: dovecot {len(a)}, ours {len(b)}")
            for x in lines:
                print(x)
    stale = [key for key in deviations if key not in used]
    for q, m in stale:
        print(f"unused deviation: {q} | {m}")
    for tag in sorted(by_tag, key=lambda t: -by_tag[t]):
        print(f"  {by_tag[tag]:4} {tag}: {tags[tag]}")
    # BODY with a word no message has decodes every message's text: the slowest kind of SEARCH.
    for label, c in [("ours", ours), ("dovecot", dovecot)]:
        runs = []
        for _ in range(5):
            t0 = time.time()
            uid_search(c, "BODY qwertyuiopzz")
            runs.append(time.time() - t0)
        runs.sort()
        print(f"BODY over {len(both)} messages ({sum(len(items[i][1]) for i in both) / 1e6:.1f} MB), {label}: "
              f"best {runs[0] * 1000:.0f} ms, median {runs[2] * 1000:.0f} ms")
    timings.sort(reverse=True)
    print(f"{len(qs)} queries over {len(both)} messages: {total} message checks, {matches} matches, "
          f"{explained_count} explained deviations, {unexplained} unexplained")
    print("slowest on ours: " + ", ".join(f"{q} {t * 1000:.0f} ms" for t, q in timings[:3]))
    return 1 if unexplained or stale else 0


def main():
    verbose = "-v" in sys.argv
    # For a closer look: --query Q (repeatable) runs only those queries, --show NAME,NAME lists those messages' results.
    args = sys.argv[1:]
    only = [args[k + 1] for k in range(len(args) - 1) if args[k] == "--query"]
    show = [n for k in range(len(args) - 1) if args[k] == "--show" for n in args[k + 1].split(",")]
    if "--ours" not in sys.argv:
        # Start our server the way the conformance tests do, and run this inside.
        command = [str(root / "tests" / "conformance" / "run.sh"), "--search-differential"] + args
        sys.exit(subprocess.run(command).returncode)
    sys.exit(run(verbose, only, show))


if __name__ == "__main__":
    main()
