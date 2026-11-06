#!/usr/bin/env python3
"""Fake clamd and spamd for mscan's tests: the failure modes the real ones will not show on demand.

    fakescan.py CLAMD_PORT SPAMD_PORT

clamd (zINSTREAM): a message containing EICAR-FAKE is "FOUND" (as Fake.Signature), HANG gets no reply, GARBAGE a
reply that is not clamd's, TOOBIG the size-limit error; anything else is OK.
spamd (CHECK): the score is the number after "X-Test-Score: " (0 without one), threshold 5.0; HANG gets no reply.
"""
import re, socketserver, struct, sys, threading


class Clamd(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.request
        command = b""
        while not command.endswith(b"\0"):
            b = s.recv(1)
            if not b:
                return
            command += b
        if command != b"zINSTREAM\0":
            s.sendall(b"UNKNOWN COMMAND\0")
            return
        data = b""
        while True:
            header = recv_exact(s, 4)
            n = struct.unpack("!I", header)[0]
            if n == 0:
                break
            data += recv_exact(s, n)
        if b"HANG" in data:
            threading.Event().wait(30)
            return
        if b"GARBAGE" in data:
            s.sendall(b"what is this\0")
        elif b"TOOBIG" in data:
            s.sendall(b"INSTREAM size limit exceeded. ERROR\0")
        elif b"EICAR-FAKE" in data:
            s.sendall(b"stream: Fake.Signature FOUND\0")
        else:
            s.sendall(b"stream: OK\0")


class Spamd(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.request
        head = b""
        while b"\r\n\r\n" not in head:
            b = s.recv(1)
            if not b:
                return
            head += b
        length = int(re.search(rb"Content-length: (\d+)", head).group(1))
        body = recv_exact(s, length)
        if b"HANG" in body:
            threading.Event().wait(30)
            return
        m = re.search(rb"X-Test-Score: (-?[\d.]+)", body)
        score = float(m.group(1)) if m else 0.0
        verdict = "True" if score >= 5.0 else "False"
        s.sendall(f"SPAMD/1.1 0 EX_OK\r\nSpam: {verdict} ; {score:.1f} / 5.0\r\n\r\n".encode())


def recv_exact(s, n):
    out = b""
    while len(out) < n:
        chunk = s.recv(n - len(out))
        if not chunk:
            raise EOFError
        out += chunk
    return out


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    clamd = Server(("127.0.0.1", int(sys.argv[1])), Clamd)
    spamd = Server(("127.0.0.1", int(sys.argv[2])), Spamd)
    threading.Thread(target=clamd.serve_forever, daemon=True).start()
    print("fakescan: ready", flush=True)
    spamd.serve_forever()
