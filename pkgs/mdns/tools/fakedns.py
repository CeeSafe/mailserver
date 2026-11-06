#!/usr/bin/env python3
"""A small authoritative DNS server for tests, on UDP and TCP.

    fakedns.py PORT ZONE.yaml

The zone is the RFC 7208 test suite's format: a mapping from names to lists of records, each a one-key mapping:
    example.test:
      - A: 192.0.2.1
      - AAAA: "2001:db8::1"
      - MX: [10, mail.example.test]
      - TXT: "v=spf1 -all"          # a list of strings for a multi-string record
      - SPF: "v=spf1 -all"          # type 99
      - PTR: host.example.test
      - CNAME: other.example.test
      - TLSA: [3, 1, 1, "d03a…"]    # usage, selector, matching type, the data in hex
      - SECURE: true                # the name is DNSSEC-signed: answers about it carry AD when the query asked
      - TIMEOUT: true               # never answer (any type)
Names not in the zone are NXDOMAIN; names in it without the asked type are NODATA (with an SOA, minimum 300).

As in the RFC 7208 suite's own harness (pyspf's testspf.py): an SPF record is also served as TXT unless the name has
a TXT record (`TXT: NONE` publishes none); a bare `TIMEOUT` entry times out queries of a type with no record listed
before it; a record whose value is TIMEOUT times out queries of its type; names under `error.` not in the zone time
out.

Special behaviours, for resolver tests:
    big.test (TXT)        answers over UDP with TC set (forcing TCP), whatever the size
    spoof.test (A)        first sends an answer with a wrong id, then the right one
    loop.test (A)         answers with a compression pointer to itself
    servfail.test         answers SERVFAIL

The zone file is re-read when it changes, so one server can serve several scenarios.
"""
import os, socket, socketserver, struct, sys, threading, ipaddress

import yaml

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "TLSA": 52, "SPF": 99}
zone_path = sys.argv[2]
_zone, _mtime = {}, None
lock = threading.Lock()


def zone():
    global _zone, _mtime
    with lock:
        m = os.stat(zone_path).st_mtime_ns
        if m != _mtime:
            data = yaml.safe_load(open(zone_path)) or {}
            _zone = {str(k).lower().rstrip("."): v for k, v in data.items()}
            _mtime = m
        return _zone


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        if label:
            b = label.encode()
            out += bytes([len(b)]) + b
    return out + b"\0"


def rdata(rtype: str, value) -> bytes:
    if rtype == "A":
        return ipaddress.IPv4Address(value).packed
    if rtype == "AAAA":
        return ipaddress.IPv6Address(value).packed
    if rtype == "MX":
        return struct.pack("!H", int(value[0])) + encode_name(value[1])
    if rtype in ("PTR", "CNAME", "NS"):
        return encode_name(value)
    if rtype == "TLSA":
        return bytes([int(value[0]), int(value[1]), int(value[2])]) + bytes.fromhex(value[3])
    if rtype in ("TXT", "SPF"):
        parts = value if isinstance(value, list) else [value]
        out = b""
        for p in parts:
            b = p.encode() if isinstance(p, str) else p
            while True:
                out += bytes([min(len(b), 255)]) + b[:255]
                b = b[255:]
                if not b:
                    break
        return out
    raise ValueError(rtype)


def expand(records):
    """A name's records as (type, value) pairs and bare "TIMEOUT" markers, with SPF records also given as TXT."""
    if records is None:
        return None
    out, generated, has_txt = [], [], False
    for r in records:
        if isinstance(r, str):
            out.append(r)
            continue
        (rtype, value), = r.items()
        if rtype == "SECURE":
            continue
        if rtype == "TXT":
            has_txt = True
        if rtype == "SPF" and value != "NONE":
            generated.append(("TXT", value))
        if value != "NONE":
            out.append((rtype, value))
    if not has_txt:
        out += generated
    return out


def parse_query(data: bytes):
    qid, flags, qd = struct.unpack("!HHH", data[:6])
    at, labels = 12, []
    while data[at]:
        n = data[at]
        labels.append(data[at + 1 : at + 1 + n].decode("latin1"))
        at += 1 + n
    qtype, qclass = struct.unpack("!HH", data[at + 1 : at + 5])
    question = data[12 : at + 5]
    return qid, ".".join(labels), qtype, question


def dnssec_ok(data: bytes) -> bool:
    """Whether the query's EDNS0 OPT record sets DO (RFC 3225)."""
    _, _, _, question = parse_query(data)
    at = 12 + len(question)
    if len(data) < at + 11 or data[at] != 0 or struct.unpack("!H", data[at + 1 : at + 3])[0] != 41:
        return False
    return (struct.unpack("!I", data[at + 5 : at + 9])[0] & 0x8000) != 0


def answer(data: bytes, tcp: bool):
    """The response bytes, or None for no answer. A list means several datagrams."""
    qid, name, qtype, question = parse_query(data)
    flags = struct.unpack("!H", data[2:4])[0]
    lname = name.lower()
    if os.environ.get("FAKEDNS_LOG"):
        print(f"query {name} {qtype} {'tcp' if tcp else 'udp'}", file=sys.stderr, flush=True)
    z = zone()
    # AD (RFC 4035 §3.2.3) as a validating resolver sets it: for a name marked SECURE, when the query set AD or DO
    # (RFC 6840 §5.7).
    asked_ad = (flags & 0x0020) != 0 or dnssec_ok(data)
    secure = any(isinstance(r, dict) and r.get("SECURE") for r in (z.get(lname) or []))
    ad = 0x0020 if (asked_ad and secure) else 0
    header = lambda rcode, an, ns=0, tc=0: struct.pack("!HHHHHH", qid, 0x8400 | ad | (tc << 9) | rcode, 1, an, ns, 0)
    if lname == "servfail.test":
        return header(2, 0) + question
    if lname == "loop.test":
        # An answer whose name is a pointer to itself (offset 12 + len(question)).
        at = 12 + len(question)
        return header(0, 1) + question + struct.pack("!H", 0xC000 | at) + struct.pack("!HHIH", 1, 1, 60, 4) + b"\1\2\3\4"
    records = expand(z.get(lname))
    if records is None:
        if lname.startswith("error."):
            return None
        body = encode_name("ns.test") + encode_name("root.test") + struct.pack("!IIIII", 1, 3600, 600, 86400, 300)
        soa = encode_name("test") + struct.pack("!HHI", 6, 1, 300) + struct.pack("!H", len(body)) + body
        return header(3, 0, 1) + question + soa
    out = []
    for item in records:
        if item == "TIMEOUT":
            if not out:
                return None
            break
        rtype, value = item
        code = TYPES[rtype]
        if code != qtype and not (rtype == "CNAME" and qtype != 5):
            continue
        if value == "TIMEOUT":
            return None
        rd = rdata(rtype, value)
        out.append(b"\xc0\x0c" + struct.pack("!HHIH", code, 1, 300, len(rd)) + rd)
        if rtype == "CNAME" and qtype != 5:
            # Follow the chain one level, as the suite's harness does.
            target = value.lower().rstrip(".")
            for t in expand(z.get(target)) or []:
                if t == "TIMEOUT":
                    continue
                tt, tv = t
                if TYPES[tt] == qtype and tv != "TIMEOUT":
                    trd = rdata(tt, tv)
                    out.append(encode_name(target) + struct.pack("!HHIH", TYPES[tt], 1, 300, len(trd)) + trd)
    if not out:
        body = encode_name("ns.test") + encode_name("root.test") + struct.pack("!IIIII", 1, 3600, 600, 86400, 300)
        soa = encode_name("test") + struct.pack("!HHI", 6, 1, 300) + struct.pack("!H", len(body)) + body
        return header(0, 0, 1) + question + soa
    if lname == "big.test" and not tcp:
        return header(0, 0, tc=1) + question
    response = header(0, len(out)) + question + b"".join(out)
    if lname == "spoof.test" and not tcp:
        wrong = struct.pack("!H", (qid + 1) & 0xFFFF) + response[2:]
        return [wrong, response]
    return response


class Udp(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        reply = answer(data, False)
        if reply is None:
            return
        for r in reply if isinstance(reply, list) else [reply]:
            sock.sendto(r, self.client_address)


class Tcp(socketserver.BaseRequestHandler):
    def handle(self):
        n = struct.unpack("!H", self.request.recv(2))[0]
        data = b""
        while len(data) < n:
            data += self.request.recv(n - len(data))
        reply = answer(data, True)
        if reply is not None:
            self.request.sendall(struct.pack("!H", len(reply)) + reply)


class ThreadedUdp(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True


class ThreadedTcp(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    port = int(sys.argv[1])
    udp = ThreadedUdp(("127.0.0.1", port), Udp)
    tcp = ThreadedTcp(("127.0.0.1", port), Tcp)
    threading.Thread(target=tcp.serve_forever, daemon=True).start()
    print("fakedns: ready", flush=True)
    udp.serve_forever()
