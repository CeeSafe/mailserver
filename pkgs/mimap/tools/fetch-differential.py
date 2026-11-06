#!/usr/bin/env python3
"""The FETCH differential: the search differential's messages (mmime's corpus and the crafted ones, with the same
flags, keywords and internal dates) are appended to a mailbox on our server and on Dovecot 2.4.5, and then every
message is fetched from both, item by item, and the responses compared byte for byte:
- FLAGS, INTERNALDATE, RFC822.SIZE, ENVELOPE, BODYSTRUCTURE, BODY, and the macros ALL, FAST and FULL;
- BODY[], BODY[HEADER], BODY[TEXT], RFC822, RFC822.HEADER, RFC822.TEXT;
- for every part number either side's BODYSTRUCTURE has: BODY[n], BODY[n.MIME], BODY[n.HEADER], BODY[n.TEXT] and
  BODY[n.HEADER.FIELDS (…)] (HEADER and TEXT are for message/rfc822 parts; elsewhere both must refuse alike);
- HEADER.FIELDS and HEADER.FIELDS.NOT (common names, a name in odd case, a name no message has), partials (inside,
  across and past the end, of length 0), and several items in one FETCH.

    pkgs/mimap/tools/fetch-differential.py [-v] [--only NAME,…] [--show N]

That one command starts our server through tests/conformance/run.sh (`--fetch-differential`) and Dovecot as the
search differential does (container `mimap-dovecot`). Inside run.sh it is run with `--ours`.

What is normalised (only what both servers may choose differently, each counted in the summary):
- the message sequence number and the UID values: responses are matched by APPEND position (and both servers gave
  the same UIDs and numbers anyway);
- a string sent as a literal by one side and quoted by the other, when the decoded bytes agree (RFC 3501 §4.3
  allows either; we send a literal for 8-bit bytes and CR/LF, which a quoted string may not hold);
- an item's name in another case or quoting: Dovecot echoes HEADER.FIELDS names upper-cased and as quoted, we echo
  them as the client spelled them, quoted only when they must be;
- the order of the items in one response (RFC 3501 sets none; Dovecot puts RFC822.SIZE before body sections);
- INTERNALDATE in another zone for the same instant (none occur: neither keeps APPEND's zone, and both show UTC,
  Dovecot its container's zone).
Every other difference must be listed in tests/fetch-deviations.txt (`item | message | tag`, `= tag: reason`), or
the run fails; a listed one that no longer differs fails it too. `-v` prints each explained difference."""
import datetime, importlib.util, pathlib, re, sys, time

here = pathlib.Path(__file__).resolve().parent
package = here.parent
root = package.parent.parent
deviations_file = package / "tests" / "fetch-deviations.txt"
sys.path.insert(0, str(package.parent / "mmime" / "tools"))
import imapsexp  # noqa: E402

spec = importlib.util.spec_from_file_location("search_differential", here / "search-differential.py")
differential = importlib.util.module_from_spec(spec)
spec.loader.exec_module(differential)

FIELDS = "FROM TO CC SUBJECT DATE MESSAGE-ID CONTENT-TYPE"
# `--full` prints whole values in differences, not their first 160 bytes.
CUT = None if "--full" in sys.argv else 160


# ---- Reading whole responses, literals included ----

def read_response(c) -> bytes:
    """One response line with its literals, as sent."""
    out = c.line()
    while (m := re.search(rb"\{(\d+)\+?\}\r\n$", out)):
        n = int(m.group(1))
        while len(c.buf) < n:
            chunk = c.sock.recv(1 << 16)
            if not chunk:
                raise EOFError("connection closed")
            c.buf += chunk
        out += c.buf[:n]
        c.buf = c.buf[n:]
        out += c.line()
    return out


def command(c, text: str) -> tuple:
    """The untagged responses and the tagged one."""
    c.n += 1
    tag = b"f%d" % c.n
    c.sock.sendall(tag + b" " + text.encode() + b"\r\n")
    untagged = []
    while True:
        resp = read_response(c)
        if resp.startswith(tag + b" "):
            return untagged, resp[len(tag) + 1:].rstrip(b"\r\n")
        untagged.append(resp)


def items_of(resp: bytes) -> list:
    """`* n FETCH (k v k v …)` as [(name, raw value bytes, parsed value)], in the order sent."""
    start = resp.index(b"(") + 1
    out = []
    while True:
        while resp[start] == 0x20:
            start += 1
        if resp[start] == ord(")"):
            return out
        end = start
        while resp[end] not in b" ()[":
            end += 1
        key = resp[start:end]
        if resp[end] == ord("["):
            close = resp.index(b"]", end)
            key, end = resp[start:close + 1], close + 1
            if resp[end] == ord("<"):
                close = resp.index(b">", end)
                key, end = resp[start:close + 1], close + 1
        value, after = imapsexp._value(resp, end)
        out.append((key.decode(), resp[end:after].lstrip(b" "), value))
        start = after


# ---- What to fetch ----

def structure_of(c, uid: int):
    untagged, status = command(c, f"UID FETCH {uid} (BODYSTRUCTURE)")
    for resp in untagged:
        for key, _, value in items_of(resp):
            if key.upper() == "BODYSTRUCTURE":
                return value
    return None


def requests(parts: list, size: int) -> list:
    """The FETCH attribute lists for one message, given its part numbers [(number, kind)] and its size."""
    out = ["FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE", "BODYSTRUCTURE", "BODY", "UID",
           "BODY.PEEK[]", "BODY.PEEK[HEADER]", "BODY.PEEK[TEXT]", "RFC822", "RFC822.HEADER", "RFC822.TEXT",
           f"BODY.PEEK[HEADER.FIELDS ({FIELDS})]", f"BODY.PEEK[HEADER.FIELDS.NOT ({FIELDS})]",
           "BODY.PEEK[HEADER.FIELDS (subject X-NO-SUCH-FIELD)]", "BODY.PEEK[HEADER.FIELDS (X-NO-SUCH-FIELD)]",
           "BODY.PEEK[HEADER.FIELDS.NOT (Received Return-Path)]", "BODY.PEEK[HEADER.FIELDS (\"Message-ID\" Date)]",
           "BODY.PEEK[]<0.100>", "BODY.PEEK[]<7.1>", f"BODY.PEEK[]<{max(size - 10, 0)}.100>",
           f"BODY.PEEK[]<{size}.10>", f"BODY.PEEK[]<{size + 1000}.10>", "BODY.PEEK[]<5.0>",
           "BODY.PEEK[TEXT]<10.50>", "BODY.PEEK[HEADER]<0.20>", "BODY.PEEK[1]<0.30>",
           "BODY.PEEK[HEADER.FIELDS (SUBJECT FROM)]<3.12>",
           # Several items at once, and the macros.
           "FAST", "ALL", "FULL",
           "UID FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODYSTRUCTURE BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)] "
           "BODY.PEEK[1]<0.20> BODY.PEEK[TEXT]<0.64>",
           "BODY.PEEK[HEADER] BODY.PEEK[TEXT] RFC822.SIZE BODY"]
    for number, kind in parts:
        out += [f"BODY.PEEK[{number}]", f"BODY.PEEK[{number}.MIME]", f"BODY.PEEK[{number}.HEADER]",
                f"BODY.PEEK[{number}.TEXT]", f"BODY.PEEK[{number}.HEADER.FIELDS ({FIELDS})]",
                f"BODY.PEEK[{number}.HEADER.FIELDS.NOT ({FIELDS})]", f"BODY.PEEK[{number}]<2.40>"]
    # A part number past the last.
    out.append(f"BODY.PEEK[{len([p for p in parts if '.' not in p[0]]) + 1}]")
    return out


# ---- Comparing ----

MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
                                      "Nov", "Dec"], 1)}


def instant(value: bytes):
    m = re.fullmatch(rb" ?(\d+)-(\w{3})-(\d{4}) (\d\d):(\d\d):(\d\d) ([+-])(\d\d)(\d\d)", value)
    if not m:
        return None
    d = datetime.datetime(int(m.group(3)), MONTHS[m.group(2).decode()], int(m.group(1)), int(m.group(4)),
                          int(m.group(5)), int(m.group(6)))
    offset = (int(m.group(8)) * 60 + int(m.group(9))) * (1 if m.group(7) == b"+" else -1)
    return d - datetime.timedelta(minutes=offset)


def item_name(key: str) -> str:
    """An item's name for matching: upper case, field names unquoted (`BODY[HEADER.FIELDS ("Date")]` is
    `BODY[HEADER.FIELDS (DATE)]`)."""
    return key.upper().replace('"', "")


def compare(theirs: tuple, mine: tuple, index: int) -> list:
    """The differences between two FETCH results [(item, kind, detail)]. A kind is 'same' (identical bytes), 'form'
    (a string quoted by one side and a literal on the other), 'name' (an item name spelled in another case or
    quoting), 'order' (the same items in another order), 'zone' (INTERNALDATE, the same instant) or 'diff'."""
    (t_untagged, t_status), (o_untagged, o_status) = theirs, mine
    t_ok, o_ok = t_status.split(b" ")[0], o_status.split(b" ")[0]
    if t_ok != o_ok:
        return [("status", "diff", f"dovecot {t_status[:120]!r}, ours {o_status[:120]!r}")]
    t_fetch = [r for r in t_untagged if re.match(rb"\* \d+ FETCH", r)]
    o_fetch = [r for r in o_untagged if re.match(rb"\* \d+ FETCH", r)]
    if len(t_fetch) != len(o_fetch):
        return [("responses", "diff", f"dovecot {len(t_fetch)} FETCH, ours {len(o_fetch)}")]
    out = []
    for t_resp, o_resp in zip(t_fetch, o_fetch):
        t_items, o_items = items_of(t_resp), items_of(o_resp)
        t_names, o_names = [item_name(k) for k, _, _ in t_items], [item_name(k) for k, _, _ in o_items]
        if sorted(t_names) != sorted(o_names):
            out.append(("items", "diff", f"dovecot {t_names}, ours {o_names}"))
            continue
        if t_names != o_names:
            out.append(("items", "order", ""))
        mine_by_name = {item_name(k): (k, raw, value) for k, raw, value in o_items}
        for key, t_raw, t_value in t_items:
            o_key, o_raw, o_value = mine_by_name[item_name(key)]
            name = item_name(key)
            if key != o_key:
                out.append((name, "name", ""))
            if name == "UID":
                # The UID values are the message's position on both sides.
                continue
            if t_raw == o_raw:
                out.append((name, "same", ""))
            elif imapsexp.canonical(t_value) == imapsexp.canonical(o_value):
                out.append((name, "form", ""))
            elif name == "INTERNALDATE" and instant(t_value) and instant(t_value) == instant(o_value):
                out.append((name, "zone", ""))
            else:
                out.append((name, "diff", f"dovecot {t_raw[:CUT]!r}, ours {o_raw[:CUT]!r}"))
    return out


def generic(item: str, request: str) -> str:
    """The item named for the deviations file: the item (`BODY[2.MIME]`, `BODYSTRUCTURE`), or for a refusal or a
    different set of items, the request."""
    return item if item not in ("status", "responses", "items") else request


def load_deviations():
    listed, tags = {}, {}
    for raw in deviations_file.read_text().splitlines():
        if not raw.strip() or raw.startswith("#"):
            continue
        if raw.startswith("= "):
            tag, reason = raw[2:].split(":", 1)
            tags[tag.strip()] = reason.strip()
            continue
        item, message, tag = [x.strip() for x in raw.split(" | ")]
        listed[(item, message)] = tag
    for key, tag in listed.items():
        if tag not in tags:
            sys.exit(f"{deviations_file.name}: undefined tag {tag!r} for {key}")
    return listed, tags


def run(verbose: bool, only: list, show: int):
    differential.ensure_dovecot()
    items = differential.messages()
    if only:
        items = [x for x in items if x[0] in only]
    dovecot = differential.Client(differential.DOVECOT, False)
    dovecot.ok("LOGIN oracle oracle")
    dovecot.command([b'DELETE "fetchdiff"'])
    dovecot.ok('CREATE "fetchdiff"')
    ours = differential.Client(differential.OURS, True)
    ours.ok(f"LOGIN {differential.USER} {differential.PASSWORD}")
    mailbox = f"fetchdiff{int(time.time())}"
    ours.ok(f'CREATE "{mailbox}"')
    started = time.time()
    their_uids, our_uids = differential.fill(dovecot, "fetchdiff", items), differential.fill(ours, mailbox, items)
    print(f"appended {len(items)} messages to each in {time.time() - started:.1f} s")
    dovecot.ok('EXAMINE "fetchdiff"')
    ours.ok(f'EXAMINE "{mailbox}"')
    deviations, tags = load_deviations()
    used, by_tag = set(), {}
    counts = {"same": 0, "form": 0, "name": 0, "order": 0, "zone": 0, "diff": 0}
    normalised = {"form": {}, "name": {}, "order": {}}
    fetches = unexplained = 0
    started = time.time()
    for i, (name, data) in enumerate(items):
        if their_uids[i] is None or our_uids[i] is None:
            print(f"  not compared: {name} (dovecot {their_uids[i]}, ours {our_uids[i]})")
            unexplained += 1
            continue
        t_uid, o_uid = their_uids[i], our_uids[i]
        parts = set()
        for c, uid in [(dovecot, t_uid), (ours, o_uid)]:
            structure = structure_of(c, uid)
            if structure is not None:
                parts |= set(imapsexp.sections(structure))
        parts = sorted(parts, key=lambda p: [int(x) for x in p[0].split(".")])
        seen_here = set()
        past = f"BODY.PEEK[{len([p for p in parts if '.' not in p[0]]) + 1}]"
        for request in requests(parts, len(data)):
            theirs = command(dovecot, f"UID FETCH {t_uid} ({request})")
            mine = command(ours, f"UID FETCH {o_uid} ({request})")
            fetches += 1
            if show and fetches <= show:
                print(f"{request}\n  dovecot {theirs!r}\n  ours    {mine!r}")
            for item, kind, detail in compare(theirs, mine, i):
                counts[kind] += 1
                if request == past:
                    item = "BODY[a part past the last]"
                if kind in ("form", "name", "order"):
                    normalised[kind][generic(item, request)] = normalised[kind].get(generic(item, request), 0) + 1
                if kind == "zone":
                    kind, item, detail = "diff", "INTERNALDATE", "the zone"
                if kind != "diff":
                    continue
                key = (generic(item, request), name)
                if key in seen_here:
                    continue
                seen_here.add(key)
                found = next((k for k in [key, (key[0], "*"), ("*", name)] if k in deviations), None)
                tag = deviations.get(found) if found else None
                if tag:
                    used.add(found)
                    by_tag[tag] = by_tag.get(tag, 0) + 1
                    if verbose:
                        print(f"  {name}: {request}: {item} ({tag}) {detail}")
                else:
                    unexplained += 1
                    print(f"UNEXPLAINED {name}: {request}: {item}: {detail}")
    stale = [key for key in deviations if key not in used]
    for item, message in stale:
        print(f"unused deviation: {item} | {message}")
    for tag in sorted(by_tag, key=lambda t: -by_tag[t]):
        print(f"  {by_tag[tag]:5} {tag}: {tags[tag]}")
    labels = {"form": "string form (literal against quoted, the same bytes)",
              "name": "item name spelling (case, quotes)", "order": "item order"}
    for kind, label in labels.items():
        if normalised[kind]:
            print(f"normalised, {label}: " + ", ".join(
                f"{k} {n}" for k, n in sorted(normalised[kind].items(), key=lambda x: -x[1])[:6]))
    total = sum(counts[k] for k in ("same", "form", "zone", "diff"))
    print(f"{fetches} FETCH commands on each over {len(items)} messages in {time.time() - started:.0f} s: "
          f"{total} items compared, {counts['same']} identical bytes, {counts['form']} string form only, "
          f"{counts['zone']} internaldate zone, {counts['diff']} different; {counts['name']} item names and "
          f"{counts['order']} responses' order normalised; {sum(by_tag.values())} message-items explained, "
          f"{unexplained} unexplained")
    return 1 if unexplained or stale else 0


def main():
    args = sys.argv[1:]
    verbose = "-v" in args
    only = [n for k in range(len(args) - 1) if args[k] == "--only" for n in args[k + 1].split(",")]
    show = next((int(args[k + 1]) for k in range(len(args) - 1) if args[k] == "--show"), 0)
    if "--ours" not in args:
        command_line = [str(root / "tests" / "conformance" / "run.sh"), "--fetch-differential"] + args
        sys.exit(__import__("subprocess").run(command_line).returncode)
    sys.exit(run(verbose, only, show))


if __name__ == "__main__":
    main()
