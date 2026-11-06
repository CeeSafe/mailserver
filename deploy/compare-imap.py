#!/usr/bin/env python3
"""Compares one account on two IMAP servers, read-only (EXAMINE): CosmoMailServer and this one after
import-cosmomail, for the shadow run before the cutover (deploy/CUTOVER.md).

    IMAP_PASSWORD=... deploy/compare-imap.py OLD_HOST:PORT NEW_HOST:PORT USER [--content] [--insecure]

For each of the old server's mailboxes: the new one has it, with the same UIDVALIDITY, UIDNEXT and uids; each
message has the same flags (\\Recent aside) and size; with --content, the same content (SHA-256 of BODY.PEEK[], with
bare LF line ends counted as CRLF, as the import stores them). Port 993 or 465-style implicit TLS is assumed unless
the port is 143 (then STARTTLS). --insecure skips certificate checks (a shadow server's self-signed certificate).
Exits 1 when anything differs, and lists what."""
import hashlib, imaplib, os, re, ssl, sys

FLAGS_SIZE = re.compile(rb"UID (\d+)|FLAGS \(([^)]*)\)|RFC822\.SIZE (\d+)")


def connect(where: str, user: str, password: str, insecure: bool):
    host, port = where.rsplit(":", 1)
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if port == "143":
        c = imaplib.IMAP4(host, 143)
        c.starttls(ssl_context=context)
    else:
        c = imaplib.IMAP4_SSL(host, int(port), ssl_context=context)
    c.login(user, password)
    return c


def mailboxes(c) -> list:
    typ, data = c.list()
    names = []
    for line in data:
        if not line:
            continue
        if isinstance(line, tuple):
            line = line[0] + line[1]
        flags = line[:line.index(b")") + 1]
        if b"\\Noselect" in flags or b"\\NonExistent" in flags:
            continue
        name = line[line.index(b")") + 1:].split(None, 1)[1].strip()
        # Skip the delimiter: "/" NAME or NIL NAME.
        name = name.split(None, 1)[1] if name.startswith((b'"/"', b"NIL", b'"."')) else name
        if name.startswith(b'"'):
            name = name[1:-1].replace(b'\\"', b'"').replace(b"\\\\", b"\\")
        names.append(name.decode())
    return names


def quote(name: str) -> str:
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


def examine(c, name: str):
    typ, data = c.select(quote(name), readonly=True)
    if typ != "OK":
        return None
    exists = int(data[0])
    validity = (c.response("UIDVALIDITY")[1] or [b"?"])[0].decode()
    uidnext = (c.response("UIDNEXT")[1] or [b"?"])[0].decode()
    messages = {}
    if exists > 0:
        typ, data = c.uid("FETCH", "1:*", "(FLAGS RFC822.SIZE)")
        for item in data:
            line = item[0] if isinstance(item, tuple) else item
            if not line:
                continue
            uid = flags = size = None
            for m in FLAGS_SIZE.finditer(line):
                if m.group(1):
                    uid = int(m.group(1))
                elif m.group(2) is not None:
                    flags = frozenset(f for f in m.group(2).decode().split() if f.lower() != "\\recent")
                elif m.group(3):
                    size = int(m.group(3))
            if uid is not None:
                messages[uid] = (flags, size)
    return {"exists": exists, "uidvalidity": validity, "uidnext": uidnext, "messages": messages}


def digest(c, uid: int) -> str:
    typ, data = c.uid("FETCH", str(uid), "(BODY.PEEK[])")
    body = next((item[1] for item in data if isinstance(item, tuple)), b"")
    return hashlib.sha256(re.sub(rb"(?<!\r)\n", b"\r\n", body)).hexdigest()


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 3 or "IMAP_PASSWORD" not in os.environ:
        sys.exit(__doc__)
    content = "--content" in sys.argv
    insecure = "--insecure" in sys.argv
    old = connect(args[0], args[2], os.environ["IMAP_PASSWORD"], insecure)
    new = connect(args[1], args[2], os.environ["IMAP_PASSWORD"], insecure)
    problems = []
    names = mailboxes(old)
    for name in names:
        a, b = examine(old, name), examine(new, name)
        if a is None:
            continue
        if b is None:
            problems.append(f"{name}: missing on the new server")
            continue
        for key in ("uidvalidity", "uidnext", "exists"):
            if a[key] != b[key]:
                problems.append(f"{name}: {key} {a[key]} (old) vs {b[key]} (new)")
        for uid in sorted(set(a["messages"]) | set(b["messages"])):
            if uid not in b["messages"]:
                problems.append(f"{name} uid {uid}: missing on the new server")
            elif uid not in a["messages"]:
                problems.append(f"{name} uid {uid}: only on the new server")
            else:
                (fa, sa), (fb, sb) = a["messages"][uid], b["messages"][uid]
                if fa != fb:
                    problems.append(f"{name} uid {uid}: flags {sorted(fa)} vs {sorted(fb)}")
                if content:
                    if digest(old, uid) != digest(new, uid):
                        problems.append(f"{name} uid {uid}: content differs")
                elif sa != sb:
                    problems.append(f"{name} uid {uid}: size {sa} vs {sb} (try --content: bare LFs become CRLF)")
        print(f"{name}: {len(a['messages'])} messages compared", file=sys.stderr)
    for c in (old, new):
        c.logout()
    for p in problems:
        print(p)
    print(f"{len(names)} mailboxes, {len(problems)} differences", file=sys.stderr)
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
