"""A small parser for IMAP response data (RFC 9051 §4): atoms, NIL, numbers, quoted strings, literals and
parenthesised lists. Strings become bytes, NIL None, numbers int, lists Python lists."""


def parse(data: bytes):
    value, at = _value(data, 0)
    return value, at


def _skip(data, at):
    while at < len(data) and data[at] == 0x20:
        at += 1
    return at


def _value(data, at):
    at = _skip(data, at)
    c = data[at]
    if c == ord("("):
        items, at = [], at + 1
        while True:
            at = _skip(data, at)
            if data[at] == ord(")"):
                return items, at + 1
            item, at = _value(data, at)
            items.append(item)
    if c == ord('"'):
        out, at = bytearray(), at + 1
        while data[at] != ord('"'):
            if data[at] == ord("\\"):
                at += 1
            out.append(data[at])
            at += 1
        return bytes(out), at + 1
    if c == ord("{"):
        end = data.index(b"}", at)
        n = int(data[at + 1 : end].rstrip(b"+"))
        start = end + 3  # "}\r\n"
        return data[start : start + n], start + n
    end = at
    while end < len(data) and data[end] not in b" ()":
        end += 1
    atom = data[at:end]
    if atom.upper() == b"NIL":
        return None, end
    if atom.isdigit():
        return int(atom), end
    return atom, end


def canonical(value) -> str:
    """One line, with every string quoted and escaped the same way, so two renderings of the same data compare
    equal whether they used literals or quoted strings."""
    if value is None:
        return "NIL"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return "(" + " ".join(canonical(v) for v in value) + ")"
    text = value.decode("utf-8", "backslashreplace")
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "\\r").replace("\n", "\\n") + '"'


def children_of(multipart):
    """A multipart's parts: the lists before its subtype (the extension data after it has lists too)."""
    out = []
    for c in multipart:
        if not isinstance(c, list):
            break
        out.append(c)
    return out


def sections(structure, prefix=""):
    """The section numbers of every part of a BODYSTRUCTURE, with what each one is: 'multipart', 'message' (an
    encapsulated message/rfc822 or global, whose HEADER and TEXT may be fetched) or 'leaf'."""
    out = []
    if isinstance(structure[0], list):  # multipart: children, then the subtype
        children = children_of(structure)
        for i, child in enumerate(children, 1):
            number = f"{prefix}{i}"
            out.append((number, kind(child)))
            out += inner(child, number)
    else:
        out.append((prefix + "1", kind(structure)))
        out += inner(structure, prefix + "1")
    return out


def kind(part):
    if isinstance(part[0], list):
        return "multipart"
    t = (part[0] or b"").lower()
    s = (part[1] or b"").lower()
    if t == b"message" and s in (b"rfc822", b"global") and len(part) > 9 and isinstance(part[8], list):
        return "message"
    return "leaf"


def inner(part, number):
    if kind(part) == "multipart":
        children = children_of(part)
        out = []
        for i, child in enumerate(children, 1):
            out.append((f"{number}.{i}", kind(child)))
            out += inner(child, f"{number}.{i}")
        return out
    if kind(part) == "message":
        body = part[8]
        if isinstance(body[0], list):
            out = []
            children = children_of(body)
            for i, child in enumerate(children, 1):
                out.append((f"{number}.{i}", kind(child)))
                out += inner(child, f"{number}.{i}")
            return out
        return [(f"{number}.1", kind(body))] + inner(body, f"{number}.1")
    return []
