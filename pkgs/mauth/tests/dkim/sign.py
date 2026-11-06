#!/usr/bin/env python3
"""Checks mauth's DKIM signer: every message of cases/ plus the edge cases below is signed with an RSA and an Ed25519
key (signkeys/, made by openssl) by examples/dkimsign, then verified by dkimpy, an independent implementation, and
by mauth's own verifier (examples/dkimcheck, its keys served by mdns's fakedns.py).

Needs dkimpy on PYTHONPATH (with dnspython, cryptography and pynacl)."""
import base64, pathlib, subprocess, sys, tempfile

import dkim

here = pathlib.Path(__file__).resolve().parent
root = here.parent.parent
sign = root / "examples" / "dkimsign" / "out" / "dkimsign"
check = root / "examples" / "dkimcheck" / "out" / "dkimcheck"
fakedns = root.parent / "mdns" / "tools" / "fakedns.py"
PORT = 55366

EDGES = {
    "trailing-space": b"From: a@signer.test\r\nTo: b@x.test\r\nSubject: spaces  \t \r\n\r\nline with spaces \t \r\n\r\n\r\n",
    "empty-body": b"From: a@signer.test\r\nSubject: empty\r\n\r\n",
    "no-final-crlf": b"From: a@signer.test\r\nSubject: x\r\n\r\nno line end",
    "folded": b"From: a@signer.test\r\nSubject: a long\r\n\tfolded   subject\r\n  more\r\nTo: one@x.test\r\nTo: two@x.test\r\n\r\nbody\r\n",
    "utf8": "From: Jörg <a@signer.test>\r\nSubject: Grüße\r\n\r\nGrüße\r\n".encode(),
    "many-fields": b"From: a@signer.test\r\nTo: b@x.test\r\nCc: c@x.test\r\nReply-To: r@x.test\r\nDate: Thu, 5 Nov 2026 10:00:00 +0000\r\n"
                   b"Message-ID: <m@signer.test>\r\nIn-Reply-To: <p@x.test>\r\nReferences: <o@x.test> <p@x.test>\r\n"
                   b"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nList-Id: <l.x.test>\r\n"
                   b"X-Not-Signed: anything\r\n\r\nhello\r\n",
    "lone-cr": b"From: a@signer.test\r\nSubject: cr\r\n\r\na\rb\r\n",
}

keys = {"rsa": here / "signkeys" / "rsa.pem", "ed": here / "signkeys" / "ed.pem"}
records = {}
for name, path in keys.items():
    p = subprocess.run([str(sign), str(path), "public"], capture_output=True, text=True, check=True).stdout.strip()
    k = "rsa" if name == "rsa" else "ed25519"
    records[f"{name}._domainkey.signer.test"] = f"v=DKIM1; k={k}; p={p}"


def dnsfunc(qname, timeout=5):
    return records.get(qname.decode().rstrip("."), "").encode()


work = pathlib.Path(tempfile.mkdtemp())
with open(work / "zone.yaml", "w") as f:
    for name, value in records.items():
        f.write(f"{name}:\n  - TXT: \"{value}\"\n")
subprocess.run(["ceesafec", "build", "-o", "out/dkimcheck"], cwd=check.parent.parent, check=True, stdout=subprocess.DEVNULL)
server = subprocess.Popen([sys.executable, str(fakedns), str(PORT), str(work / "zone.yaml")], stdout=subprocess.PIPE)
server.stdout.readline()

messages = {p.stem: p.read_bytes() for p in sorted((here / "cases").glob("*.eml"))}
messages.update(EDGES)
passed = failed = 0
try:
    for name, message in messages.items():
        source = work / "in.eml"
        source.write_bytes(message)
        for selector, path in keys.items():
            out = subprocess.run([str(sign), str(path), "signer.test", selector, str(source)], capture_output=True)
            if out.returncode != 0:
                failed += 1
                print(f"FAIL {name}/{selector}: not signed: {out.stderr.decode().strip()}")
                continue
            signed = out.stdout
            (work / "signed.eml").write_bytes(signed)
            theirs = dkim.verify(signed, dnsfunc=dnsfunc)
            ours = subprocess.run([str(check), str(PORT), str(work / "signed.eml")], capture_output=True, text=True)
            first = (ours.stdout.split("\n") or [""])[0]
            if theirs and first == "pass":
                passed += 1
            else:
                failed += 1
                print(f"FAIL {name}/{selector}: dkimpy {theirs}, mauth {first!r}")
                print(signed[:600].decode("latin-1"))
finally:
    server.kill()
print(f"{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
