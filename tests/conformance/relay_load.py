#!/usr/bin/env python3
"""Relay throughput: puts N messages for remote recipients straight into the queue (one blob, a recipient each) and
times how long the relay takes to deliver them all to the fake MX. run.sh --relay-load N; POOL_SIZE=0 for a
connection per message."""
import subprocess, sys, time


def sql(query):
    return subprocess.run(["docker", "exec", "ceesafe-pg-test", "psql", "-At", "-U", "cee", "-d", "mailserver_test",
                           "-c", query], capture_output=True, check=True, text=True).stdout.strip()


n = int(sys.argv[1])
# A blob to send: any message, stored by delivering one locally.
import smtplib
with smtplib.SMTP("127.0.0.1", 2525) as c:
    c.ehlo("remote.test")
    c.sendmail("load@remote.test", ["carol@example.org"], "Subject: relay load\r\n\r\n" + "x" * 4000 + "\r\n")
time.sleep(0.5)
sql(f"INSERT INTO queue (blob, size, sender, recipients) SELECT m.blob, m.size, 'relay@example.org', "
    f"ARRAY['load' || g || '@remote.test'] FROM (SELECT blob, size FROM messages ORDER BY uid DESC LIMIT 1) m, "
    f"generate_series(1, {n}) g")
started = time.time()
limit = float(sys.argv[2]) if len(sys.argv) > 2 else 300
while int(sql("SELECT count(*) FROM queue")) > 0:
    time.sleep(0.1)
    if time.time() - started > limit:
        print("STUCK:", sql("SELECT count(*), count(claim), min(attempts), max(attempts) FROM queue"))
        sys.exit(1)
elapsed = time.time() - started
print(f"{n} messages relayed in {elapsed:.2f} s: {n / elapsed:.0f} messages/s")
