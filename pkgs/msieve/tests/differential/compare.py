#!/usr/bin/env python3
"""Differential test of msieve against Pigeonhole's sieve-test (dovecot/dovecot:2.4.5).

    compare.py RUN_BINARY [CASE_FILTER]

Each case in cases.py is a script, a message and an envelope. Both interpreters run it; their actions are brought
to one form (see examples/run) and compared. Pigeonhole runs in one long-lived container, with `docker exec`.
"""
import os, re, subprocess, sys, tempfile

sys.path.insert(0, os.path.dirname(__file__))
from cases import CASES, MESSAGES

IMAGE = "dovecot/dovecot:2.4.5"
CONTAINER = "msieve-pigeonhole"


def start_container(work):
    subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True)
    subprocess.run(["docker", "run", "-d", "--name", CONTAINER, "-v", f"{work}:/w", "-i", "--entrypoint", "/bin/sh", IMAGE],
                   check=True, capture_output=True)


def pigeonhole(case_dir, sender, recipient):
    args = ["docker", "exec", CONTAINER, "sieve-test"]
    if sender is not None:
        args += ["-f", sender or "<>"]
    args += ["-a", recipient, f"/w/{case_dir}/t.sieve", f"/w/{case_dir}/m.eml"]
    p = subprocess.run(args, capture_output=True, text=True)
    if p.returncode != 0 and "Performed actions" not in p.stdout:
        return ["error"], p.stdout + p.stderr
    out, implicit = [], False
    lines = p.stdout.splitlines()
    i = 0
    vacation = None
    while i < len(lines):
        line = lines[i]
        if line.startswith("Implicit keep"):
            implicit = True
        m = re.match(r" \* store message in folder: (.*)", line)
        if m:
            flags = ""
            if i + 1 < len(lines):
                f = re.match(r"\s+\+ add IMAP flags: (.*)", lines[i + 1])
                if f:
                    flags = f.group(1).strip()
                    i += 1
            out.append(f"store {m.group(1)}" + (f" [{flags}]" if flags else ""))
        m = re.match(r" \* redirect message to:? <?([^>]*)>?", line)
        if m:
            out.append(f"redirect {m.group(1).strip()}")
        if line.startswith(" * send vacation message"):
            vacation = {}
        elif vacation is not None:
            m = re.match(r"    => (\w+)\s*: (.*)", line)
            if m:
                key = m.group(1)
                vacation[key] = m.group(2)
            elif line.startswith("START MESSAGE"):
                body = []
                i += 1
                while i < len(lines) and lines[i] != "END MESSAGE":
                    body.append(lines[i])
                    i += 1
                days = int(vacation.get("seconds", "0")) // 86400
                reason = "\\n".join(body)
                while reason.endswith("\\n"):
                    reason = reason[:-2]
                out.append(f"vacation days={days} subject={vacation.get('subject', '')} "
                           f"handle={vacation.get('handle', '')} reason={reason}")
                vacation = None
            elif line != "" and key == "handle":
                vacation["handle"] += "\\n" + line
        i += 1
    if "runtime error" in p.stdout or "runtime error" in p.stderr:
        out.insert(0, "runtime-error")
    return out, p.stdout + p.stderr


def ours(binary, case_dir, sender, recipient):
    args = [binary, f"{case_dir}/t.sieve", f"{case_dir}/m.eml", sender or "", recipient]
    p = subprocess.run(args, capture_output=True, text=True)
    out = []
    for line in p.stdout.splitlines():
        if line.startswith("error"):
            return ["error"], p.stdout
        if line.startswith("runtime-error"):
            out.append("runtime-error")
            continue
        line = re.sub(r" from=.*? handle=", " handle=", line)
        if line.startswith("vacation"):
            while line.endswith("\\n"):
                line = line[:-2]
        out.append(line)
    if p.returncode != 0:
        out.append(f"exit {p.returncode}")
    return out, p.stdout + p.stderr


def main():
    binary = os.path.abspath(sys.argv[1])
    only = sys.argv[2] if len(sys.argv) > 2 else None
    work = tempfile.mkdtemp(prefix="msieve-diff-")
    os.chmod(work, 0o755)
    start_container(work)
    failures = 0
    ran = 0
    try:
        for n, case in enumerate(CASES):
            name, script, message = case["name"], case["script"], case.get("message", "plain")
            if only and only not in name:
                continue
            sender = case.get("from", "sender@example.org")
            recipient = case.get("to", "user@example.com")
            d = f"c{n}"
            os.makedirs(f"{work}/{d}", exist_ok=True)
            with open(f"{work}/{d}/t.sieve", "w") as f:
                f.write(script)
            with open(f"{work}/{d}/m.eml", "wb") as f:
                f.write(MESSAGES[message].replace(b"\n", b"\r\n"))
            os.chmod(f"{work}/{d}", 0o755)
            expected, raw = pigeonhole(d, sender, recipient)
            os.chdir(work)
            got, mine = ours(binary, d, sender, recipient)
            ran += 1
            if "expect" in case:
                expected = case["expect"]
            if got != expected:
                failures += 1
                print(f"FAIL {name}\n  pigeonhole: {expected}\n  msieve:     {got}")
                if os.environ.get("VERBOSE"):
                    print(raw, mine)
    finally:
        subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True)
    print(f"{ran - failures}/{ran} cases agree")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
