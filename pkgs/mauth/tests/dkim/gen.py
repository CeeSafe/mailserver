#!/usr/bin/env python3
"""Builds the DKIM differential set in cases/: messages signed by dkimpy (an independent implementation) in many
variants, some then tampered with, plus MimeKit's real Gmail messages and RFC 8463's example. Writes zone.yaml (the
public keys, for mdns's fakedns.py) and expected.txt (`<case> <pass|fail> ...`: dkimpy's verdict per signature).

    PYTHONPATH=<dir with dkimpy> tests/dkim/gen.py <mimekit TestData/dkim dir>

The output is checked in; this is only needed to change the set."""
import base64, pathlib, random, re, subprocess, sys

import dkim
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

here = pathlib.Path(__file__).resolve().parent
cases = here / "cases"
cases.mkdir(exist_ok=True)
for f in cases.glob("*.eml"):
    f.unlink()
rng = random.Random(7208)
zone, expected = {}, []

def crlf(b: bytes) -> bytes:
    return re.sub(rb"(?<!\r)\n", b"\r\n", b)

def rsa_key(bits):
    k = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                          serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return pem, "v=DKIM1; k=rsa; p=" + base64.b64encode(pub).decode()

def ed_key():
    k = ed25519.Ed25519PrivateKey.generate()
    raw = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw), "v=DKIM1; k=ed25519; p=" + base64.b64encode(pub).decode()

keys = {}
for name, maker in (("rsa2048", lambda: rsa_key(2048)), ("rsa1024", lambda: rsa_key(1024)), ("ed", ed_key)):
    private, record = maker()
    keys[name] = private
    zone[f"{name}._domainkey.example.org"] = [{"TXT": [record[i:i + 250] for i in range(0, len(record), 250)]}]
# A revoked key.
zone["revoked._domainkey.example.org"] = [{"TXT": "v=DKIM1; k=rsa; p="}]

BODIES = [
    b"Hello.\r\n",
    b"",
    b"\r\n\r\n\r\n",
    b"Line with trailing spaces   \r\n\tIndented\t \tline\r\n\r\n\r\n",
    b"No final newline",
    b"A lone CR\rinside\r\n",
    b"x" * 5000 + b"\r\n" + b"  spaced   out  \r\n" * 50,
    b"--boundary\r\nContent-Type: text/plain\r\n\r\npart\r\n--boundary--\r\n",
]
HEADERS = (b"From: Alice <alice@example.org>\r\nTo: bob@example.net\r\nSubject:  Spaced   subject \r\n"
           b"Date: Thu, 05 Nov 2026 10:00:00 +0000\r\nMessage-ID: <%d@example.org>\r\n"
           b"X-Folded: first\r\n\tsecond  line\r\n")

def sign(message, selector, canon, include, length=False, algo=b"rsa-sha256"):
    return dkim.sign(message, selector.encode(), b"example.org", keys[selector], canonicalize=canon,
                     include_headers=include, length=length, signature_algorithm=algo)

def verdicts(message):
    """dkimpy's verdict for each signature, top first."""
    d = dkim.DKIM(message)
    out = []
    sigs = [h for h in d.headers if h[0].lower() == b"dkim-signature"]
    for i in range(len(sigs)):
        try:
            ok = d.verify(idx=i, dnsfunc=lambda name, timeout=5: dns_txt(name))
        except Exception:
            ok = False
        out.append("pass" if ok else "fail")
    return out

def dns_txt(name):
    n = name.decode().rstrip(".").lower()
    recs = zone.get(n)
    if not recs:
        return None
    v = recs[0]["TXT"]
    return ("".join(v) if isinstance(v, list) else v).encode()

n = 0
def add(name, message):
    global n
    n += 1
    (cases / f"{n:03}-{name}.eml").write_bytes(message)
    expected.append(f"{n:03}-{name} " + " ".join(verdicts(message)))

canons = [(b"simple", b"simple"), (b"relaxed", b"relaxed"), (b"relaxed", b"simple"), (b"simple", b"relaxed")]
for bi, body in enumerate(BODIES):
    for canon in canons:
        for selector, algo in (("rsa2048", b"rsa-sha256"), ("ed", b"ed25519-sha256")):
            message = HEADERS % rng.randrange(10**9) + b"\r\n" + body
            include = [b"from", b"to", b"subject", b"date", b"message-id", b"x-folded"]
            signed = sign(message, selector, canon, include, algo=algo) + message
            tag = f"b{bi}-{canon[0].decode()[0]}{canon[1].decode()[0]}-{selector}"
            add(tag, signed)
# Over-signing (a header named twice, and one that is absent), l=, a 1024-bit key, two signatures.
message = HEADERS % 1 + b"\r\nBody.\r\n"
add("oversigned", sign(message, "rsa2048", (b"relaxed", b"relaxed"),
                       [b"from", b"from", b"subject", b"reply-to", b"to"]) + message)
add("length", sign(message, "rsa2048", (b"relaxed", b"simple"), [b"from", b"to"], length=True) + message)
add("rsa1024", sign(message, "rsa1024", (b"relaxed", b"relaxed"), [b"from", b"subject"]) + message)
both = sign(message, "rsa2048", (b"relaxed", b"relaxed"), [b"from"]) + message
add("two-signatures", sign(both, "ed", (b"simple", b"simple"), [b"from", b"subject"], algo=b"ed25519-sha256") + both)
# Tampering: each must fail (dkimpy says so too).
base = sign(message, "rsa2048", (b"relaxed", b"relaxed"), [b"from", b"to", b"subject"]) + message
add("tampered-body", base.replace(b"Body.", b"Bodies."))
add("tampered-subject", base.replace(b"Spaced   subject", b"Other subject"))
add("relaxed-whitespace-ok", base.replace(b"Subject:  Spaced   subject", b"Subject: Spaced subject"))
add("added-to-unsigned-header", base.replace(b"Date:", b"X-Added: yes\r\nDate:"))
lsigned = sign(message, "rsa2048", (b"relaxed", b"relaxed"), [b"from"], length=True) + message
add("length-appended", lsigned + b"Appended after l=.\r\n")
add("revoked", base.replace(b"s=rsa2048", b"s=revoked"))

# MimeKit's real messages (Gmail, 2015) and RFC 8463's example, with their published keys.
if len(sys.argv) > 1:
    src = pathlib.Path(sys.argv[1])
    gmail = "".join(l for l in (src / "gmail.pub").read_text().splitlines() if "-----" not in l)
    zone["20120113._domainkey.gmail.com"] = [{"TXT": [f"k=rsa; p={gmail}"[i:i + 250] for i in range(0, len(gmail) + 9, 250)]}]
    zone["brisbane._domainkey.football.example.com"] = [{"TXT": "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="}]
    zone["test._domainkey.football.example.com"] = [{"TXT": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB"}]
    for f in ("gmail.msg", "related.msg", "multipart-no-end-boundary.msg", "rfc8463-example.msg"):
        add("mimekit-" + f.split(".")[0], crlf((src / f).read_bytes()))

import yaml
yaml.safe_dump(zone, open(here / "zone.yaml", "w"), width=1000)
(here / "expected.txt").write_text("\n".join(expected) + "\n")
print(f"{n} cases")
