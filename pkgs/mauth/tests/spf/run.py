#!/usr/bin/env python3
"""Runs the RFC 7208 test suite (rfc7208-tests.yml, from pyspf, the SPF council's suite) against mauth's SPF:
each scenario's zone is served by mdns's tools/fakedns.py, each test runs examples/spfcheck.

    tests/spf/run.py [-v] [-k NAME]"""
import argparse, os, pathlib, subprocess, sys, tempfile, time

import yaml

here = pathlib.Path(__file__).resolve().parent
root = here.parent.parent
fakedns = root.parent / "mdns" / "tools" / "fakedns.py"
spfcheck = root / "examples" / "spfcheck" / "out" / "spfcheck"
PORT = 55354

# Where mauth knowingly differs from the suite's expected text.
DEVIATIONS = {
    # The suite expects %{ir} of "CAFE:BABE::1" with upper-case nibbles (its input's case). RFC 7208 does not
    # say; mauth writes lower case, as the RFC's own example (§7.4) does. DNS names compare without case.
    "v-macro-ip6": "explanation case",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-v", action="store_true")
    ap.add_argument("-k")
    args = ap.parse_args()
    subprocess.run(["ceesafec", "build", "-o", "out/spfcheck"], cwd=spfcheck.parent.parent, check=True,
                   stdout=subprocess.DEVNULL)
    zone = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
    zone.write("{}")
    zone.close()
    server = subprocess.Popen([sys.executable, str(fakedns), str(PORT), zone.name], stdout=subprocess.PIPE)
    server.stdout.readline()
    passed = failed = 0
    try:
        for scenario in yaml.safe_load_all(open(here / "rfc7208-tests.yml")):
            with open(zone.name, "w") as f:
                yaml.safe_dump(scenario["zonedata"], f)
            time.sleep(0.01)
            for name, test in scenario["tests"].items():
                if args.k and args.k not in name:
                    continue
                out = subprocess.run([str(spfcheck), str(PORT), test["host"], test["mailfrom"], test["helo"]],
                                     capture_output=True, text=True)
                lines = out.stdout.split("\n")
                result, explanation = (lines + ["", ""])[:2]
                want = test["result"] if isinstance(test["result"], list) else [test["result"]]
                ok = result in want
                if ok and "explanation" in test and result == "fail":
                    expected = test["explanation"]
                    ok = explanation == expected or (expected == "DEFAULT" and explanation == "")
                if not ok and name in DEVIATIONS and result in want:
                    ok = explanation.lower() == str(test.get("explanation", "")).lower()
                if ok:
                    passed += 1
                    continue
                failed += 1
                print(f"FAIL {scenario['description']}: {name} (§{test['spec']}): got {result!r} "
                      f"{explanation!r}, want {want} {test.get('explanation', '')!r}")
                if args.v:
                    print("   ", test.get("description", ""), "|", out.stderr.strip()[:200])
    finally:
        server.kill()
        os.unlink(zone.name)
    print(f"{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
