#!/usr/bin/env python3
"""Compares mmime with Dovecot over the corpus: for each tests/corpus/<m>.eml, runs examples/inspect and checks its
size, ENVELOPE, BODYSTRUCTURE, BODY and every section's bytes (HEADER.FIELDS and HEADER.FIELDS.NOT included) against
tests/oracle/<m>.txt, and its decoded Subject and From display names against Python's email package.

    tools/differential.py [-v] [-k NAME] [--chunk N]

Differences listed in tests/deviations.txt (`<message> <field>  # why`) are reported but allowed. Exit status 1 when
anything else differs."""
import argparse, email, email.policy, hashlib, pathlib, subprocess, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import imapsexp

here = pathlib.Path(__file__).resolve().parent.parent
corpus, oracle = here / "tests" / "corpus", here / "tests" / "oracle"
inspect = here / "examples" / "inspect" / "out" / "inspect"


def ours(path: pathlib.Path, chunk: int):
    raw = subprocess.run([str(inspect), str(path), str(chunk)], capture_output=True, check=True).stdout
    data = path.read_bytes()
    out, at = {}, 0
    while at < len(raw):
        end = raw.index(b"\n", at)
        line = raw[at:end].decode()
        at = end + 1
        key, _, rest = line.partition(" ")
        if key in ("envelope", "bodystructure", "body"):
            n = int(rest)
            value, _ = imapsexp.parse(raw[at : at + n])
            out[key] = imapsexp.canonical(value)
            at += n + 1
        elif key == "fields":
            name, n = rest.split(" ")
            piece = raw[at : at + int(n)]
            out["section " + name] = f"{len(piece)} {hashlib.sha256(piece).hexdigest()}"
            at += int(n) + 1
        elif key in ("subject", "from-names"):
            n = int(rest)
            out["decoded " + key] = raw[at : at + n].decode("utf-8", "replace")
            at += n + 1
        elif key == "bodytext":  # for tools/body-differential.py
            index, n = rest.split(" ")
            out["bodytext " + index] = raw[at : at + int(n)]
            at += int(n) + 1
        elif key in ("size", "parts"):
            out[key] = rest
        elif key == "section":
            name, start, stop = rest.split(" ")
            piece = data[int(start) : int(stop)]
            out["section " + name] = f"{len(piece)} {hashlib.sha256(piece).hexdigest()}"
    return out


def expected(path: pathlib.Path):
    out = {}
    for line in path.read_text().splitlines():
        key, _, rest = line.partition(" ")
        if key == "section":
            name, _, value = rest.partition(" ")
            out["section " + name] = value
        else:
            out[key] = rest
    return out


def python_decoded(path: pathlib.Path):
    """What Python's email package (policy.default) reads in the Subject and the From display names."""
    out = {}
    message = email.message_from_bytes(path.read_bytes(), policy=email.policy.default)
    # Raw 8-bit text with no charset decodes to surrogates or U+FFFD in Python: there is no answer to compare with.
    # (mmime reads such text as UTF-8 if it is, else as Latin-1, so the bytes stay recoverable.)
    unknown = lambda text: any(0xDC80 <= ord(c) <= 0xDCFF or c == "\ufffd" for c in text)
    try:
        subject = message["subject"]
        if subject is not None and not unknown(str(subject)):
            out["decoded subject"] = str(subject).strip()
    except Exception:
        pass
    try:
        sender = message["from"]
        if sender is not None and not any(unknown(a.display_name) for a in sender.addresses):
            out["decoded from-names"] = [a.display_name for a in sender.addresses]
    except Exception:
        pass
    return out


def same_names(want, mine: str) -> bool:
    """Python reads no name from a comment (`nsb (Nathaniel Borenstein)`); mmime does, as Dovecot's ENVELOPE does. So
    only the names Python found are compared."""
    got = mine.split("\n")[:-1] if mine != "<missing>" else []
    if len(got) != len(want):
        return False
    return all(w == "" or w == g for w, g in zip(want, got))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-v", action="store_true", help="show both values of each difference")
    ap.add_argument("-k", help="only messages whose name contains this")
    ap.add_argument("--chunk", type=int, default=4096)
    args = ap.parse_args()
    allowed = {}
    deviations = here / "tests" / "deviations.txt"
    if deviations.exists():
        for line in deviations.read_text().splitlines():
            line = line.split("#")[0].strip()
            if line:
                message, field = line.split(None, 1)
                allowed[(message, field)] = True
    failures = allowedCount = checked = 0
    for path in sorted(corpus.glob("*.eml")):
        if args.k and args.k not in path.name:
            continue
        want = expected(oracle / (path.stem + ".txt"))
        want.update(python_decoded(path))
        got = ours(path, args.chunk)
        for key, value in want.items():
            if value == "NIL" and key.startswith("section "):
                continue  # Dovecot has no such section; ours may (an empty range), which is fine
            checked += 1
            mine = got.get(key, "<missing>")
            if mine == value or (key == "decoded from-names" and same_names(value, mine)):
                continue
            if (path.stem, key) in allowed or (path.stem, key.split(" ")[0]) in allowed:
                allowedCount += 1
                continue
            failures += 1
            print(f"{path.stem}: {key}")
            if args.v:
                show = lambda v: str(v)[:600].encode("utf-8", "backslashreplace").decode("utf-8")
                print(f"  oracle: {show(value)}")
                print(f"  mmime:  {show(mine)}")
    print(f"{checked} checks, {failures} differences, {allowedCount} allowed deviations")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
