#!/usr/bin/env python3
"""A fake receiving SMTP server for mqueue's tests: what real MX hosts do, good and bad, on demand.

    fakemx.py BASE_PORT LOG_DIR [CERT KEY]

Listens on 127.0.0.1, one behaviour per port:
    BASE     ESMTP with PIPELINING, SIZE 1000000, 8BITMIME, SMTPUTF8, and STARTTLS when CERT and KEY are given
    BASE+1   greets 421 (busy)
    BASE+2   an old server: EHLO is 502, HELO works, no extensions
    BASE+3   accepts the connection and never says anything
    BASE+4   closes the connection in the middle of DATA
    BASE+5   offers STARTTLS, says 220, then sends garbage instead of a TLS handshake
    BASE+6   ESMTP without PIPELINING (one command at a time), no STARTTLS
Every port closes a connection that has been idle for 3 seconds, as real servers do (without a reply).
By the recipient's local part: reject* gets 550 5.1.1, defer* 451 4.2.1; if any accepted recipient starts with
datafail the final dot gets 554 5.6.0, with tempdata 451 4.3.0.
Each message received is written to LOG_DIR as NNNN.json: port, helo, tls, mail (the whole MAIL line), rcpts
(accepted), data (latin-1 text of the bytes as received, before un-stuffing), and commands (every line received).
"""
import json, os, socket, socketserver, ssl, sys, threading, time

BASE = int(sys.argv[1])
LOG = sys.argv[2]
CERT = sys.argv[3] if len(sys.argv) > 4 else None
KEY = sys.argv[4] if len(sys.argv) > 4 else None
counter = [0]
lock = threading.Lock()


class Session:
    def __init__(self, sock, mode):
        self.sock, self.mode, self.buf, self.tls = sock, mode, b"", False
        self.commands = []

    def send(self, text):
        self.sock.sendall(text.encode() + b"\r\n")

    def line(self):
        self.sock.settimeout(3)
        while b"\n" not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError
            self.buf += chunk
        line, _, self.buf = self.buf.partition(b"\n")
        line = line.rstrip(b"\r")
        self.commands.append(line.decode("latin-1"))
        return line

    def capabilities(self):
        caps = ["250-fake.mx.test"]
        if self.mode == 0:
            caps += ["250-PIPELINING", "250-SIZE 1000000", "250-8BITMIME", "250-SMTPUTF8"]
            if CERT and not self.tls:
                caps.append("250-STARTTLS")
        if self.mode == 5 and not self.tls:
            caps.append("250-STARTTLS")
        caps.append("250 ENHANCEDSTATUSCODES")
        return "\r\n".join(caps)

    def run(self, port):
        if self.mode == 3:
            time.sleep(30)
            return
        if self.mode == 1:
            self.send("421 4.3.2 fake.mx.test busy, try later")
            return
        self.send("220 fake.mx.test ESMTP")
        helo, mail, rcpts = "", "", []
        while True:
            line = self.line()
            verb = line[:4].upper()
            if verb == b"EHLO":
                if self.mode == 2:
                    self.send("502 5.5.1 EHLO not implemented")
                    continue
                helo = line[5:].decode()
                self.send(self.capabilities())
            elif verb == b"HELO":
                helo = line[5:].decode()
                self.send("250 fake.mx.test")
            elif line.upper() == b"STARTTLS":
                self.send("220 2.0.0 go ahead")
                if self.mode == 5:
                    self.sock.sendall(b"this is not TLS\r\n" * 4)
                    return
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(CERT, KEY)
                self.sock = context.wrap_socket(self.sock, server_side=True)
                self.tls, self.buf = True, b""
            elif verb == b"MAIL":
                mail, rcpts = line.decode("utf-8", "replace"), []
                self.send("250 2.1.0 ok")
            elif verb == b"RCPT":
                address = line[line.index(b"<") + 1:line.rindex(b">")].decode("utf-8", "replace")
                local = address.split("@")[0]
                if local.startswith("reject"):
                    self.send("550 5.1.1 <%s>: no such user" % address)
                elif local.startswith("defer"):
                    self.send("451 4.2.1 <%s>: try again later" % address)
                else:
                    rcpts.append(address)
                    self.send("250 2.1.5 ok")
            elif verb == b"DATA":
                if not rcpts:
                    self.send("554 5.5.1 no valid recipients")
                    continue
                self.send("354 go ahead")
                if self.mode == 4:
                    self.sock.recv(1)
                    return  # drop the connection in the middle of DATA
                while True:
                    whole = b"\r\n" + self.buf
                    end = whole.find(b"\r\n.\r\n")
                    if end >= 0:
                        data, self.buf = whole[2:end + 2], whole[end + 5:]
                        break
                    chunk = self.sock.recv(65536)
                    if not chunk:
                        raise EOFError
                    self.buf += chunk
                if any(r.split("@")[0].startswith("datafail") for r in rcpts):
                    self.send("554 5.6.0 message content rejected")
                elif any(r.split("@")[0].startswith("tempdata") for r in rcpts):
                    self.send("451 4.3.0 temporary failure")
                else:
                    with lock:
                        counter[0] += 1
                        n = counter[0]
                    record = {"port": port, "helo": helo, "tls": self.tls, "mail": mail, "rcpts": rcpts,
                              "data": data.decode("latin-1"), "commands": self.commands}
                    with open(os.path.join(LOG, "%04d.json.tmp" % n), "w") as f:
                        json.dump(record, f)
                    os.rename(os.path.join(LOG, "%04d.json.tmp" % n), os.path.join(LOG, "%04d.json" % n))
                    self.send("250 2.0.0 ok: queued as fake%d" % n)
                self.commands = []
            elif verb == b"RSET":
                mail, rcpts = "", []
                self.send("250 2.0.0 ok")
            elif verb == b"QUIT":
                self.send("221 2.0.0 bye")
                return
            else:
                self.send("500 5.5.2 unknown command")


def handler(mode, port):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                Session(self.request, mode).run(port)
            except (EOFError, ConnectionError, ssl.SSLError, OSError):
                pass
    return H


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    os.makedirs(LOG, exist_ok=True)
    for mode in range(7):
        server = Server(("127.0.0.1", BASE + mode), handler(mode, BASE + mode))
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print("fakemx: ready", flush=True)
    threading.Event().wait()
