#!/usr/bin/env python3
"""Writes tests/oracle/<message>.txt: what Dovecot (IMAP4rev2, the dovecot/dovecot Docker image) makes of each
corpus message. It appends the message, then fetches its size, ENVELOPE, BODYSTRUCTURE, and the length and SHA-256
of every body section: HEADER, TEXT, each part, each part's MIME header, and HEADER/TEXT of embedded messages; and
HEADER.FIELDS and HEADER.FIELDS.NOT (of the names in `FIELDS`) of the message and of embedded messages.

    docker run -d --name mmime-dovecot -e USER_PASSWORD=oracle -p 127.0.0.1:51143:31143 \
        -v "$PWD/tools/dovecot-oracle.conf:/etc/dovecot/conf.d/oracle.conf:ro" dovecot/dovecot:2.4.5
    tools/dovecot-oracle.py

Each line is `key value`; values are canonical (tools/imapsexp.py), so literals and quoted strings compare equal."""
import hashlib, imaplib, pathlib, re, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import imapsexp

here = pathlib.Path(__file__).resolve().parent.parent
corpus, oracle = here / "tests" / "corpus", here / "tests" / "oracle"
# The names of the HEADER.FIELDS and HEADER.FIELDS.NOT sections (as examples/inspect asks for them).
FIELDS = "FROM TO CC SUBJECT DATE MESSAGE-ID CONTENT-TYPE"


def response_bytes(data):
    """imaplib splits a response at its literals; join it back into the bytes the server sent."""
    out = b""
    for item in data:
        if isinstance(item, tuple):
            out += item[0] + b"\r\n" + item[1]  # imaplib drops the CRLF after {n}
        elif item is not None:
            out += item
    return out


def item(raw: bytes, name: bytes):
    """The value of FETCH data item `name` in a whole `* n FETCH (...)` response."""
    start = raw.index(b"(") + 1
    while True:
        while raw[start] == 0x20:
            start += 1
        end = start
        while raw[end] not in b" ()[":
            end += 1
        key = raw[start:end]
        if raw[end] == ord("["):
            close = raw.index(b"]", end)
            key, end = raw[start : close + 1], close + 1
            if raw[end] == ord("<"):
                end = raw.index(b">", end) + 1
        value, after = imapsexp._value(raw, end)
        if key.upper() == name.upper():
            return value
        start = after


def fetch(imap, uid, what: str, name: bytes):
    typ, data = imap.uid("FETCH", str(uid), f"({what})")
    if typ != "OK" or not data or data[0] is None:
        return None
    return item(response_bytes(data), name)


def main():
    imap = imaplib.IMAP4("127.0.0.1", 51143)
    imap.login("oracle", "oracle")
    oracle.mkdir(parents=True, exist_ok=True)
    files = sorted(corpus.glob("*.eml"))
    for n, path in enumerate(files, 1):
        imap.select("INBOX")
        imap.uid("STORE", "1:*", "+FLAGS.SILENT", r"(\Deleted)")
        imap.expunge()
        message = path.read_bytes()
        typ, data = imap.append("INBOX", None, None, message)
        if typ != "OK":
            print(f"{path.name}: APPEND refused: {data}", file=sys.stderr)
            continue
        uid = int(re.search(rb"APPENDUID \d+ (\d+)", data[0]).group(1))
        lines = [f"size {fetch(imap, uid, 'RFC822.SIZE', b'RFC822.SIZE')}"]
        envelope = fetch(imap, uid, "ENVELOPE", b"ENVELOPE")
        structure = fetch(imap, uid, "BODYSTRUCTURE", b"BODYSTRUCTURE")
        body = fetch(imap, uid, "BODY", b"BODY")
        lines.append("envelope " + imapsexp.canonical(envelope))
        lines.append("bodystructure " + imapsexp.canonical(structure))
        lines.append("body " + imapsexp.canonical(body))
        wanted = ["HEADER", "TEXT", "HEADER.FIELDS", "HEADER.FIELDS.NOT"]
        for number, kind in imapsexp.sections(structure):
            wanted.append(number)
            wanted.append(number + ".MIME")
            if kind == "message":
                wanted += [number + x for x in (".HEADER", ".TEXT", ".HEADER.FIELDS", ".HEADER.FIELDS.NOT")]
        for section in wanted:
            asked = f"{section} ({FIELDS})" if "HEADER.FIELDS" in section else section
            value = fetch(imap, uid, f"BODY.PEEK[{asked}]", f"BODY[{asked}]".encode())
            if value is None:
                lines.append(f"section {section} NIL")
            else:
                lines.append(f"section {section} {len(value)} {hashlib.sha256(value).hexdigest()}")
        (oracle / (path.stem + ".txt")).write_text("\n".join(lines) + "\n")
        if n % 25 == 0:
            print(f"{n}/{len(files)}")
    imap.logout()
    print(f"tests/oracle: {len(files)} messages")


if __name__ == "__main__":
    main()
