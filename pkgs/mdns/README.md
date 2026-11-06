# mdns

An async DNS stub resolver for the mail server: A, AAAA, MX, TXT, PTR, CNAME and TLSA, asking recursive resolvers
(from `/etc/resolv.conf` or the configuration) and caching their answers.

```ceesafe
let resolver = Resolver.fromSystem()?;            // or Resolver.create(servers, 53)
var answer = DnsAnswer.create();
await resolver.query("example.org", TYPE_MX, mut answer)?;
for (i in 0..answer.count()) {
    let host = answer.dataText(i);                // MX host; answer.preference(i)
}
```

- **Transport.**
  - UDP with EDNS0 at 1232 bytes, the 2020 DNS flag day's size.
  - A truncated answer is asked again over TCP (RFC 7766).
  - Each server gets 2 s, twice round the list.
- **Spoofing.**
  - Every query uses a new socket, so the source port is random, and a random 16-bit id.
  - Datagrams from another address, or with another id or question, are ignored rather than taken.
  - Only records on the CNAME chain from the question's name are kept, so an answer cannot slip in records for
    other names.
- **Malformed answers.**
  - Compression pointers must point backwards, so loops are impossible.
  - Names are capped at 255 bytes, and every length is bounds-checked.
  - A truncation anywhere is refused.
- **Cache.**
  - Answers are kept for their TTL, capped at a day; negative answers for the SOA minimum, capped at 15 minutes
    (RFC 2308).
  - It holds 1024 buckets of 16 entries and is shared by every task.
  - SERVFAIL is not cached; it comes back as an answer with that rcode, which callers read as a temporary failure.
- **Addresses.** `IpAddress` is 16 bytes, with IPv4 mapped into IPv6. `parseIp`, `appendIp`, `inNetwork` (CIDR) and
  `appendReverseName` (`in-addr.arpa` and `ip6.arpa`) handle them.
- **DNSSEC.** `DnsAnswer.authenticated` is the AD bit. That is meaningful only from a validating resolver you trust,
  as DANE needs.

## Tests

- `tests/run.sh` starts `tools/fakedns.py` and runs the tests, which also cover parsing addresses and malformed
  messages. `tools/fakedns.py` is a small authoritative server reading `tests/zone.yaml`; its hostile cases are a
  timeout, a forced truncation, a spoofed reply ahead of the real one, a compression loop and SERVFAIL.
- `examples/lookup NAME TYPE [SERVER]` matched `dig +short` for MX, A, AAAA, PTR and NXDOMAIN against real domains.
  This network drops TXT queries for every tool, `dig` included, so TXT was checked only against the fake server.
- **Not yet:** merging identical queries that are in flight at once (the cache covers repeats), and DNS over TLS.
