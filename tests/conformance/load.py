#!/usr/bin/env python3
"""A rough SMTP load test: CLIENTS connections each send COUNT messages to alice@example.org on the MX port, reusing
the connection. Prints messages/s. Each message is stored (blob fsynced, rows committed) before its 250."""
import smtplib, sys, threading, time

clients = int(sys.argv[1]) if len(sys.argv) > 1 else 16
count = int(sys.argv[2]) if len(sys.argv) > 2 else 100
body = "From: load@remote.test\r\nSubject: load\r\n\r\n" + ("lorem ipsum dolor sit amet " * 40 + "\r\n") * 4
errors = []

def worker(n):
    try:
        with smtplib.SMTP("127.0.0.1", 2525) as c:
            c.ehlo("load.test")
            for i in range(count):
                c.sendmail("load@remote.test", ["alice@example.org"], body + f"{n}-{i}\r\n")
    except Exception as e:
        errors.append(e)

started = time.time()
threads = [threading.Thread(target=worker, args=(n,)) for n in range(clients)]
for t in threads: t.start()
for t in threads: t.join()
elapsed = time.time() - started
total = clients * count
print(f"{total} messages of {len(body)} bytes in {elapsed:.2f} s: {total / elapsed:.0f} messages/s, {len(errors)} errors")
