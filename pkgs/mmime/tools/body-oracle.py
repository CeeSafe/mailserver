#!/usr/bin/env python3
"""Writes tests/body-oracle/<m>.txt for each tests/corpus/<m>.eml: what Python's email package reads in the body of
every text part, for tools/body-differential.py to compare with mmime's `appendPartText`.

    tools/body-oracle.py

Each part comes from `Message.walk()` (depth first, embedded messages and multiparts included: the order of
`MessageMeta.parts`). A text/* leaf's body is `get_payload(decode=True)` (base64, quoted-printable and uuencode
undone), then decoded with its charset, errors replaced. Lines:

    python VERSION
    parts N
    text I LENGTH SHA256 WS-SHA256      text of part I: its UTF-8 length and hash, and the hash with whitespace collapsed
    skip I REASON                       not compared: a charset Python does not know, or a part inside a message/*
                                        type other than rfc822 and global, which IMAP reads as one leaf

One choice is ours, not Python's: a part without a charset, or with US-ASCII, is decoded as UTF-8 (errors
replaced), the reading IMAP's SEARCH gives US-ASCII text; Python would turn every 8-bit byte into U+FFFD."""
import codecs, email, email.policy, hashlib, pathlib, sys

here = pathlib.Path(__file__).resolve().parent.parent
corpus, oracle = here / "tests" / "corpus", here / "tests" / "body-oracle"


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def describe(path: pathlib.Path) -> str:
    message = email.message_from_bytes(path.read_bytes(), policy=email.policy.default)
    parts = list(message.walk())
    lines = [f"python {sys.version.split()[0]}", f"parts {len(parts)}"]
    # Python also reads message/partial, message/delivery-status, message/external-body and the like as holding
    # messages; IMAP (Dovecot, mmime) reads only message/rfc822 and message/global so, the others are leaves.
    opaque = set()

    def mark(part, inside):
        if inside:
            opaque.add(id(part))
        if part.is_multipart():
            kind = part.get_content_type()
            hides = inside or (kind.startswith("message/") and kind not in ("message/rfc822", "message/global"))
            for child in part.get_payload():
                mark(child, hides)

    mark(message, False)
    for i, part in enumerate(parts):
        if part.is_multipart() or part.get_content_maintype() != "text":
            continue
        if id(part) in opaque:
            lines.append(f"skip {i} inside-message-leaf")
            continue
        payload = part.get_payload(decode=True) or b""
        charset = part.get_content_charset()
        if charset is None or charset in ("us-ascii", "ascii"):
            charset = "utf-8"
        try:
            codecs.lookup(charset)
        except LookupError:
            lines.append(f"skip {i} unknown-charset {charset}")
            continue
        text = payload.decode(charset, "replace")
        lines.append(f"text {i} {len(text.encode('utf-8', 'surrogatepass'))} {sha(text)} {sha(' '.join(text.split()))}")
    return "\n".join(lines) + "\n"


def main():
    oracle.mkdir(exist_ok=True)
    count = 0
    for path in sorted(corpus.glob("*.eml")):
        (oracle / (path.stem + ".txt")).write_text(describe(path))
        count += 1
    print(f"{count} messages")


if __name__ == "__main__":
    main()
