#!/usr/bin/env python3
"""Compares the decoded text of every text part (mmime's `appendPartText`, HTML not stripped) with what Python's
email package reads (tests/body-oracle/, from tools/body-oracle.py), over the corpus.

    tools/body-differential.py [-v] [-k NAME]

Parts are matched by their index in a depth-first walk. When a message's part count differs from Python's (Python
also opens message/delivery-status, message/partial and the like, and the parsers split some malformed multiparts
differently; the structure itself is checked against Dovecot by tools/differential.py), each of Python's texts is
looked for among mmime's by content instead. Differences listed in tests/body-deviations.txt (`<message> <part>  # why`) are reported but allowed. Exit status 1 when anything
else differs."""
import argparse, hashlib, pathlib, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from differential import corpus, here, ours

oracle = here / "tests" / "body-oracle"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-v", action="store_true", help="show the start of mmime's text for each difference")
    ap.add_argument("-k", help="only messages whose name contains this")
    args = ap.parse_args()
    allowed = set()
    deviations = here / "tests" / "body-deviations.txt"
    if deviations.exists():
        for line in deviations.read_text().splitlines():
            line = line.split("#")[0].strip()
            if line:
                message, part = line.split()
                allowed.add((message, part))
    checked = failures = allowedCount = whitespace = skipped = structure = structureParts = extra = 0
    structureFound = unfound = opaque = 0
    for path in sorted(corpus.glob("*.eml")):
        if args.k and args.k not in path.name:
            continue
        want = {}
        parts = None
        for line in (oracle / (path.stem + ".txt")).read_text().splitlines():
            words = line.split(" ")
            if words[0] == "parts":
                parts = words[1]
            elif words[0] == "text":
                want[words[1]] = (int(words[2]), words[3], words[4])
            elif words[0] == "skip":
                if words[2] == "unknown-charset":
                    skipped += 1
                else:
                    opaque += 1
                want[words[1]] = None
        got = ours(path, 4096)
        if got.get("parts") != parts:
            # Split differently: each of Python's texts is looked for among mmime's, by content.
            structure += 1
            mine = {(len(v), hashlib.sha256(v).hexdigest()) for k, v in got.items() if k.startswith("bodytext ")}
            collapse = lambda v: " ".join(v.decode("utf-8", "surrogateescape").split()).encode("utf-8", "surrogateescape")
            mineWs = {hashlib.sha256(collapse(v)).hexdigest() for k, v in got.items() if k.startswith("bodytext ")}
            for index, value in want.items():
                if value is None:
                    continue
                structureParts += 1
                if value[:2] in mine:
                    structureFound += 1
                elif (path.stem, index) in allowed:
                    allowedCount += 1
                elif value[2] in mineWs:
                    whitespace += 1
                    print(f"{path.stem}: part {index} (Python's numbering): found, whitespace only")
                else:
                    unfound += 1
                    print(f"{path.stem}: part {index} (Python's numbering; {got.get('parts')} parts, Python {parts}): not found")
            continue
        for index, value in want.items():
            if value is None:
                continue
            checked += 1
            mine = got.get("bodytext " + index)
            text = mine.decode("utf-8", "surrogateescape") if mine is not None else None
            if mine is not None and (len(mine), hashlib.sha256(mine).hexdigest()) == value[:2]:
                continue
            if (path.stem, index) in allowed:
                allowedCount += 1
                continue
            if text is not None and hashlib.sha256(" ".join(text.split()).encode("utf-8", "surrogateescape")).hexdigest() == value[2]:
                whitespace += 1
                print(f"{path.stem}: part {index}: whitespace only")
            else:
                failures += 1
                print(f"{path.stem}: part {index}: {'missing' if mine is None else 'differs'}")
            if args.v and mine is not None:
                print("  mmime: " + repr(text[:300]))
        for key in got:
            if key.startswith("bodytext ") and key.split(" ")[1] not in want:
                extra += 1
                print(f"{path.stem}: part {key.split(' ')[1]}: text for mmime only")
    differences = failures + whitespace + extra + unfound
    print(
        f"{checked + structureParts} checks, {differences} differences ({whitespace} in whitespace only, {extra} parts "
        f"text for mmime only, {unfound} not found), {allowedCount} allowed deviations. {structure} messages split "
        f"differently from Python: their {structureParts} text parts were looked for by content, {structureFound} "
        f"found. Not compared: {skipped} parts in a charset Python does not know, {opaque} parts Python finds inside "
        f"leaves (message/partial, message/delivery-status, …)."
    )
    return 1 if differences else 0


if __name__ == "__main__":
    sys.exit(main())
