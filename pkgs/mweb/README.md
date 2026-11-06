# mweb

The server's HTTP side: the listeners, the public endpoints, certificates, and the admin JSON API.

- `server.cee`: four kinds of listener (`[http] http`, `https`, `admin`, and `proxied`: plain HTTP from a
  TLS-terminating proxy, with `X-Forwarded-*` trusted and no admin API); one task per connection, persistent
  connections, malformed requests answered and closed. The client's address (the forwarded one behind a proxy) goes
  in `Request.peer`, for the failed-login guard. EWS's GetStreamingEvents is streamed from here (chunked).
- Groupware: `/dav` and `/.well-known/caldav|carddav` (pkgs/mdav), `/Microsoft-Server-ActiveSync` (pkgs/meas) and
  `/EWS/Exchange.asmx` (pkgs/mews) on HTTPS, the admin listener and `proxied`; plain port 80 answers 403, since their
  passwords travel in every request. Bodies up to `RequestLimits.uploadBody` (50 MiB) on those paths.
- `wellknown.cee`: ACME HTTP-01 challenges, MTA-STS policies (HTTPS only, from `domains.mta_sts_*`), Thunderbird
  autoconfig, Outlook autodiscover (POX XML with IMAP, SMTP and, with `[http] advertise_exchange`, EWS; the
  mobilesync schema for ActiveSync; v2 JSON), `/api/health`. On the admin and proxied listeners, `X-Forwarded-Host`
  is trusted (a reverse proxy in front); on public ones it is not.
- `certs.cee`: the certificate files are polled; a change is installed for new TLS connections on every listener,
  and a broken one is refused.
- `renew.cee`: ACME renewal (`[acme]`), with `pkgs/macme`; a self-signed placeholder at first start; the key is kept
  across renewals (DANE).
- `jwt.cee`: HS256 tokens (RFC 7519); only HS256 is accepted.
- `admin*.cee`: the admin API for CosmoMailAdmin's Nuxt frontend.
  - Same routes and JSON shapes as the C# server (snake_case or camelCase, route by route, as there).
  - Postgres builds the JSON, and request bodies go to SQL as one jsonb parameter.
  - Every change is written to `audit_logs`.

Running the admin UI: build the frontend and run its Nitro server with `COSMOMAIL_ADMIN_API_BASE` set to the
admin listener (for example `http://127.0.0.1:9184`), and set `[admin] jwt_secret`. Make a login with
`mailserver add-admin admin PASSWORD`. The admin listener must stay on loopback, or behind the UI's server.

Tests: `ceesafec test` (JWT with RFC 7515's example, MTA-STS text, XML), and `tests/conformance/run.sh --web`,
`--admin` and `--acme`.
