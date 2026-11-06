# mscan

Streaming clients for the two content scanners mail servers use: ClamAV's clamd (`zINSTREAM`) and SpamAssassin's
spamd (the SPAMC protocol). The caller sends the message in pieces of any size, as it holds them (msmtp: memory,
then its spool file), so nothing is copied whole.

```ceesafe
var clam = await ClamdScan.open(address)?;
await clam.send(piece)?;  …
match (await clam.finish()?) { VirusVerdict.Clean => …, VirusVerdict.Infected => clam.signature, VirusVerdict.Unavailable => … }

var spam = await SpamdScan.open(address, length, "alice@example.org")?;
await spam.send(piece)?;  …
let score = await spam.finish()?;     // score.tenths: 6.9 is 69
```

- **Replies:**
  - clamd's NUL-terminated reply is read whole: a partial read could otherwise miss `FOUND`, a bug the C# server
    once had and fixed.
  - spamd's status code is checked, and its `Spam: True ; 15.0 / 5.0` line is parsed strictly.
  - Error replies, such as clamd's size limit, and garbled ones give `Unavailable` or unscored, never `Clean`.
- **Timeouts** are the caller's (`Async.timeout`), so a hung scanner holds one session for at most that long.
- **`Breaker`:** after 3 failures in a row a scanner is skipped for 30 s, so a dead clamd costs each message nothing
  rather than a full timeout. One success closes it again.

## Tests

`tests/run.sh` runs:
- **against `tools/fakescan.py`:** the failure modes (a hang, a garbled reply, the size-limit error, refused
  connections) and score parsing;
- **against real ClamAV and SpamAssassin in Docker** when they are running (commands in `tests/run.sh`): ClamAV
  finds EICAR and passes a clean message, SpamAssassin scores GTUBE 1000 and passes ham.

The EICAR and GTUBE strings are built at run time, so no file here looks like malware to a scanner on your machine.
