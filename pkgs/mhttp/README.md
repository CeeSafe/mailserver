# mhttp

HTTP/1.1 and JSON for the mail server's web side: small, strict, and written for the few requests a mail server
serves and sends (autoconfig, MTA-STS, ACME, the admin API), not for general web serving.

- `request.cee`: requests (RFC 9112).
  - Limits: 8 KB request and field lines, 100 fields and 64 KB of them, a configurable body limit.
  - Bodies by Content-Length or chunked; `Expect: 100-continue` is honoured.
  - Ambiguous framing is refused, not guessed: Content-Length together with Transfer-Encoding, two different lengths,
    or a coding other than chunked (RFC 9112 §6.1, the request-smuggling shapes).
  - Folded lines and white space before a colon are refused (§5.1, §5.2).
- `response.cee`: responses with Content-Length, a Date, and no body (but the length) for HEAD.
  - 1xx, 204 and 304 carry no length.
  - CR and LF in a header value are refused.
- `json.cee`: JSON (RFC 8259).
  - `JsonWriter` builds a document and reports a failed allocation once, at `finish`.
  - `JsonDocument` checks a whole document once (UTF-8, escapes and surrogate pairs, number syntax, nesting at most
    64 deep), then keeps it as a tape of nodes: lookups are index walks with no tree of allocations.
- `client.cee`: one request per connection, over TLS for https URLs (the certificate checked against the
  configuration's roots), the whole response read into memory, no redirects followed. Used by the ACME client.
- `challenges.cee`: the ACME HTTP-01 challenges being served, shared by every worker thread.
- `time.cee`: RFC 3339 times.

Tests: `ceesafec test` (JSON accept and refuse cases, request parsing and refusals, rendering). The server's side is
tested end to end by `tests/conformance/run.sh --web`.
