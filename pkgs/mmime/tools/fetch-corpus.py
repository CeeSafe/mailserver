#!/usr/bin/env python3
"""Builds tests/corpus/ from MimeKit's test data at a pinned commit (MIT): its single messages and the messages of
its mbox files (jwz's MIME torture collection among them), one .eml each, with CRLF line endings as SMTP stores them.

The corpus is not checked in; tests/oracle/ (what Dovecot made of each message) is."""
import pathlib, re, shutil, subprocess, sys, tempfile

COMMIT = "03097f0474d554284c1fb73692e95aecc1003bec"
REPO = "https://github.com/jstedfast/MimeKit.git"
here = pathlib.Path(__file__).resolve().parent.parent
out = here / "tests" / "corpus"

def crlf(data: bytes) -> bytes:
    return re.sub(rb"(?<!\r)\n", b"\r\n", data)

def main():
    work = pathlib.Path(tempfile.mkdtemp(prefix="mimekit-"))
    try:
        run = lambda *a: subprocess.run(a, cwd=work, check=True, capture_output=True)
        run("git", "init", "-q")
        run("git", "remote", "add", "origin", REPO)
        run("git", "config", "core.sparseCheckout", "true")
        (work / ".git" / "info" / "sparse-checkout").write_text("UnitTests/TestData/\n")
        run("git", "fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", COMMIT)
        run("git", "checkout", "-q", "FETCH_HEAD")
        data = work / "UnitTests" / "TestData"
        if out.exists():
            shutil.rmtree(out)
        out.mkdir(parents=True)
        count = 0
        for folder in ("messages", "compliance", "partial"):
            for f in sorted((data / folder).iterdir()):
                if f.suffix not in (".eml", ".txt") or f.name.startswith("body."):
                    continue
                (out / f"{folder}-{f.stem}.eml").write_bytes(crlf(f.read_bytes()))
                count += 1
        for f in sorted((data / "mbox").glob("*.mbox.txt")):
            # Split at "From " lines; drop the separator line, un-escape ">From " (mboxrd).
            messages, current = [], None
            for line in f.read_bytes().splitlines(keepends=True):
                if line.startswith(b"From "):
                    current = []
                    messages.append(current)
                elif current is not None:
                    current.append(re.sub(rb"^>(>*From )", rb"\1", line))
            stem = f.name[: -len(".mbox.txt")]
            for i, lines in enumerate(messages):
                body = b"".join(lines)
                if body.endswith(b"\n\n"):
                    body = body[:-1]  # the blank line before the next separator
                (out / f"mbox-{stem}-{i:03}.eml").write_bytes(crlf(body))
                count += 1
        print(f"tests/corpus: {count} messages from MimeKit {COMMIT[:12]}")
    finally:
        shutil.rmtree(work, ignore_errors=True)

if __name__ == "__main__":
    sys.exit(main())
