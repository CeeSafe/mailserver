#!/usr/bin/env python3
"""Upserts DNS records in a Cloudflare zone, DNS-only (never proxied: mail cannot pass Cloudflare's proxy).

    CF_ZONE=example.com cf-dns.py records.json [--dry-run]

records.json: [{"type": "A", "name": "mail.example.com", "content": "203.0.113.10"}, {"type": "MX", ...,
"priority": 10}, {"type": "SRV", "name": "_imaps._tcp.example.com", "data": {...}}, ...]. A record of the same type
and name is replaced (for TXT: the same name and the same "v=..." tag), so running it again changes nothing. The API
token (Zone -> DNS -> Edit for that zone) is read from CF_TOKEN_FILE (default ~/.config/cloudflare/<first label of
the zone>.token, e.g. example.token) and never printed.
"""
import json, os, sys, urllib.request, urllib.error

ZONE = os.environ.get("CF_ZONE") or sys.exit("set CF_ZONE")
API = "https://api.cloudflare.com/client/v4"
TOKEN = open(os.path.expanduser(os.environ.get("CF_TOKEN_FILE",
                                                f"~/.config/cloudflare/{ZONE.split('.')[0]}.token"))).read().strip()


def call(method, path, body=None):
    req = urllib.request.Request(API + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        d = json.load(e)
        raise SystemExit(f"{method} {path}: {e.code} {d.get('errors')}")


def tag(content):
    c = content.strip('"')
    return c.split(";", 1)[0].split(" ", 1)[0] if c.startswith("v=") else None


def same(existing, want):
    if existing["type"] != want["type"] or existing["name"] != want["name"]:
        return False
    if want["type"] == "TXT":
        return tag(existing["content"]) == tag(want["content"])
    return True


def main():
    records = json.load(open(sys.argv[1]))
    dry = "--dry-run" in sys.argv
    zones = call("GET", f"/zones?name={ZONE}")["result"]
    if not zones:
        raise SystemExit("zone not found")
    zid = zones[0]["id"]
    current = []
    page = 1
    while True:
        r = call("GET", f"/zones/{zid}/dns_records?per_page=100&page={page}")
        current += r["result"]
        if page >= r["result_info"]["total_pages"]:
            break
        page += 1
    for want in records:
        body = {"type": want["type"], "name": want["name"], "ttl": want.get("ttl", 1)}
        if want["type"] == "SRV":
            body["data"] = want["data"]
        else:
            body["content"] = want["content"]
        if want["type"] in ("A", "AAAA", "CNAME"):
            body["proxied"] = False
        if "priority" in want:
            body["priority"] = want["priority"]
        match = [e for e in current if same(e, want)]
        shown = want.get("content") or json.dumps(want.get("data"))
        if match:
            e = match[0]
            unchanged = (e.get("content") == body.get("content") if "content" in body else True) and \
                e.get("priority", body.get("priority")) == body.get("priority") and e.get("proxied", False) is False
            if want["type"] == "SRV":
                unchanged = e.get("data", {}) == {**e.get("data", {}), **want["data"]}
            if unchanged:
                print(f"same     {want['type']:5} {want['name']} {shown}")
                continue
            print(f"update   {want['type']:5} {want['name']} {shown}")
            if not dry:
                call("PUT", f"/zones/{zid}/dns_records/{e['id']}", body)
        else:
            print(f"create   {want['type']:5} {want['name']} {shown}")
            if not dry:
                call("POST", f"/zones/{zid}/dns_records", body)


if __name__ == "__main__":
    main()
