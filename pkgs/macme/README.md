# macme

An ACME client (RFC 8555) for one job: certify the server's names with HTTP-01.

- `acme.cee`, `AcmeClient`:
  - reads the directory, registers the account (or finds the one its key already has), and orders the names;
  - publishes each HTTP-01 key authorization through the server's `ChallengeStore`, tells the CA to check, and polls
    the authorization;
  - finalizes with a CSR and polls the order (honouring Retry-After, at most 10 s, 60 polls), then downloads the
    chain.
  - Every POST is a flattened RS256 JWS with a fresh nonce; badNonce is retried once (§6.5).
  - Problem documents are kept for the log (`problem()`, `detail()`).
- `keys.cee`:
  - RSA 2048 keys (through CeeSafeLibs/pkey);
  - the account JWK and its thumbprint (RFC 7638);
  - JWS signing, and PEM in and out;
  - certificate requests (PKCS #10) with a subjectAltName for every name, and self-signed placeholder certificates.
- `der.cee`: the DER this needs. It writes TLVs; reads an RSA SubjectPublicKeyInfo; and reads a certificate's
  validity and DNS names.

Renewal policy (when to renew, which names, writing the files) is the server's: `pkgs/mweb/src/renew.cee`.

Tests:
- `ceesafec test`: self-signed certificates and CSRs read back and verify; the JWS verifies with the account key;
  the fixture certificate parses.
- `tools/fakeacme.py`: a strict fake CA for `tests/conformance/run.sh --acme`. It checks every JWS (signature,
  nonce, URL, jwk versus kid), validates HTTP-01 by fetching the token from the server, and checks the CSR's
  signature and names before issuing a real certificate. Every 3rd POST gets badNonce, and a name can be refused.
- The outputs were also checked with OpenSSL (`openssl req -verify`, `openssl verify`, matching moduli).

Not done: ARI (ACME renewal information), external account binding, ECDSA account keys, DNS-01, and certificate revocation.
