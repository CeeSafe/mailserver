#!/usr/bin/env python3
"""Checks mauth's DKIM verifier against dkimpy's verdicts (expected.txt) on the cases gen.py made, serving their
keys (zone.yaml) with mdns's fakedns.py."""
import pathlib, subprocess, sys

here = pathlib.Path(__file__).resolve().parent
root = here.parent.parent
fakedns = root.parent / "mdns" / "tools" / "fakedns.py"
check = root / "examples" / "dkimcheck" / "out" / "dkimcheck"
PORT = 55355

subprocess.run(["ceesafec", "build", "-o", "out/dkimcheck"], cwd=check.parent.parent, check=True, stdout=subprocess.DEVNULL)
server = subprocess.Popen([sys.executable, str(fakedns), str(PORT), str(here / "zone.yaml")], stdout=subprocess.PIPE)
server.stdout.readline()
passed = failed = 0
try:
    for line in (here / "expected.txt").read_text().split("\n"):
        if not line:
            continue
        name, *want = line.split()
        out = subprocess.run([str(check), str(PORT), str(here / "cases" / (name + ".eml"))], capture_output=True, text=True)
        got = [l for l in out.stdout.split("\n") if l]
        verdicts = ["pass" if g == "pass" else "fail" for g in got]
        if verdicts == want:
            passed += 1
        else:
            failed += 1
            print(f"FAIL {name}: got {got}, dkimpy says {want}", out.stderr.strip()[:200])
finally:
    server.kill()
print(f"{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
