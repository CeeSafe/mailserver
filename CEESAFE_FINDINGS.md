# CeeSafe findings from the mail server port

These findings come from porting CosmoMailServer to CeeSafe 0.15.0. That work covers PostgresClient, sha256, tls,
encoding, diskio, bcrypt, pkey, and the mailserver packages mstore, mmime, msmtp, mdns, mauth, mscan and msieve,
about 25,000 lines.

The running log, in the order the findings were met, is `~/dev/CeeSafeLibs/NOTES-ceesafe-0.14.md`. This file sorts
them by what to fix first. Each entry gives what happens, a minimal repro where one exists, the workaround used in
this code, and a suggested fix.

**Re-checked:** on 2026-11-05 with `ceesafec 0.15.0`, and §1.4 with 0.15.1. Entries marked ✔ were run again that day
and still reproduce. The others were seen while writing the named package and have not been re-run.

## Status in 0.18.0 (checked 2026-11-05)

Each entry was run again with its repro or snippet under `ceesafec 0.17.0`, and the entries fixed by ADR 0074
under 0.18.0. The sections below keep the original
descriptions. "Fixed in" names the first release where the entry passed: 0.16.0, 0.17.0 and 0.18.0 were checked
directly, and the 0.16.1 entry comes from its release notes.

| Entry | Status | Fixed in |
|---|---|---|
| 1.1 panic on `await listener.accept()` in a library test | **Fixed:** the repro's test passes | 0.16.0 |
| 1.2 missing drop glue for `AsyncTcpListener` | **Fixed:** the repro's test passes | 0.16.0 |
| 1.3 `Async.run(Async.scope(…))` loses its result | **Fixed:** now a clear error, N0342 (write an async fn) | 0.16.0 |
| 1.4 stale wake from `Async.blocking` | **Fixed:** the repro passes 6 of 6; relay load passes 14 of 14 (below) | 0.16.1 |
| 2.1 `pushBE('P')` writes four bytes | **Fixed:** now N0265, which asks for `pushBE<u8>` | 0.16.0 |
| 2.2 `"{x}"` printed literally | **Fixed:** warning N0400 (`'\{'` for a real brace) | 0.17.0 |
| 2.3 `Console.write` panics on non-UTF-8 | Not re-tested (a documentation fix) | — |
| 2.4 a dependency's `@test`s collected | **Fixed:** only the root package's tests run | 0.16.0 |
| 3.1 `??` and optional methods | **Fixed:** `??`, `isSome()` and `isNull()` (no `valueOr`; `??` covers it) | 0.16.0 |
| 3.2 borrowing a temporary (N0247) | **Fixed:** `use(make().view())` works | 0.17.0 |
| 3.3 two-phase borrows (N0242) | **Fixed:** `fail(mut s, s.n[0])` works (PostgresClient's `await` case not re-tested) | 0.17.0 |
| 3.4 loop variable's type | **Fixed:** `take(i)` and `0..list.count()` both give `usize` | 0.16.0 |
| 3.5 `==` on slices, enums, arrays | **Fixed:** all three | 0.16.0 |
| 3.6 match arms as value blocks | **Fixed:** a block's final expression is its value | 0.17.0 |
| 3.7 generics over `void` | **Fixed:** `Ok(v)` binds a unit payload, so `conv(act())` runs | 0.18.0 |
| 3.8 `let _ = …` | **Fixed** | 0.16.0 |
| 3.9 moving captures (`async move`) | **Fixed:** an `async move` child or timeout body moves its captures; the relay's stream handoff is gone | 0.18.0 |
| 3.10 regions and methods | **Mostly fixed:** method region parameters (not in interfaces) and results tied to the struct's region (0.18.0). Open: a `var` view (N0246), left for its own ADR | 0.18.0 |
| 3.11 literals and constants | **Fixed:** `.length` of a const array (0.16.0); raw `"""` literals and `const` in structs and impls (0.18.0). mstore's SQL generator is gone | 0.18.0 |
| 3.12 optional field as optional borrow | **Fixed:** `f(r.cfg)`, `asBorrow()`, `asBorrowMut()` | 0.18.0 |
| 3.13 `for` over `split` | **Fixed:** `for` takes any value with `next(borrow mut this) -> T?` | 0.18.0 |
| 3.14 `as` from `usize` to `i64` | **Fixed:** `as` stays lossless; `checkedTruncate<i64>(n)` and `saturatingTruncate` take integers, and N0208 names them | 0.18.0 |
| 4 a dependency's name as a local | **Fixed:** a local or parameter may shadow it (warning N0401 when ambiguous); items keep N0315 | 0.18.0 |
| 4.1 a never-returning type | **Fixed:** `-> never` (main's `die`) | 0.18.0 |

§1.4 under the mail server: 8 of 8 runs with 300 messages (4 workers, one thread), and 6 of 6 with 1,000 messages
over STARTTLS. The full conformance suite passes (48 tests, 5 skipped). With 1,000 messages over STARTTLS, the
connection pool gives 319–338 messages/s against 211–276 with it off.

The workarounds these entries cost were removed from the mail server with 0.18.0. The stream handoff vector
(§3.9), the hand-written `next()` loops (§3.13), the dead `Process.exit` after `die` (§4.1), msieve's `Problem`
struct (§3.3), the enum `match` predicates (§3.5), sieve's void-only `stored` adapter (§3.7), the listener tests
that forced drop glue (§1.2), and mstore's SQL generator (§3.11) are gone. The relay's `tryTls` flag stays: it is
the opportunistic retry in the clear, not a §3.12 workaround.

---

## 1. Compiler bugs

### 1.1 ✔ The compiler panics on `await listener.accept()` in a library test

Repro: `~/dev/CeeSafeLibs/repros/types-index-panic/` (`ceesafec test`). The library's only function is:

```ceesafe
async fn accepted(listener: borrow AsyncTcpListener) -> bool {
    match (await listener.accept()) { Ok(_) => { return true; } Err(_) => { return false; } }
}
```

```
ceesafe panic: index out of bounds at src/types/types.cee:311:61
```

- **Workaround:** none needed in msmtp; it does not hit this exact shape.

### 1.2 ✔ Drop glue for `AsyncTcpListener` is missing from the C

Repro: `~/dev/CeeSafeLibs/repros/listener-drop-glue/` (`ceesafec test`). It takes a library that only *borrows*
listeners, with an `Async.tasks` accept loop that `spawnSend`s a child.

```
error: call to undeclared function 'ceeM_16AsyncTcpListener_drop'
```

- An executable that creates a listener builds fine.
- **Workaround:** msmtp has a test that binds a listener, so the glue gets emitted. mqueue, which links msmtp, needed
  the same test (seen again 2026-11-05).

### 1.3 ✔ `Async.run(Async.scope(…))` in sync code loses its result

```ceesafe
enum E { Oom, Bad }
fn main() {
    var y = 0;
    let outcome = Async.run(Async.scope(E.Oom, (s) => {
        s.spawn(async () => { y = 2; return Ok(); });
    }));
    match (outcome) { Ok() => { Console.writeLine(y); } Err(_) => {} }
}
```

- `ceesafec run --interp` fails with `N0212: 'outcome' is read here but may not have been assigned a value`.
- `Async.run(Async.all(…))` does the same.
- **Declared first and assigned later, it compiles but is wrong:** the assignment never takes effect, and the `Err`
  branch runs.
- **Workaround:** put the scope inside an `async fn` and `Async.run(thatFn())`.

### 1.4 ✔ (fixed in 0.16.1) A stale wake from `Async.blocking` corrupts the async runtime: stalls, crashes, aborts

This is a runtime bug (`runtime/hosted/ceesafe_rt_async.c`), and the most serious item in this file: any program that
calls `Async.blocking` and later awaits `Async.timeout`, `race` or `all` (or any scope) can hang or crash at random.

Repro: `~/dev/CeeSafeLibs/repros/stale-wake/` (`ceesafec build -o repro --cflag -O2 && ./repro`). Four tasks each
loop 20,000 times over `await Async.blocking(() => 1u32)` then `await Async.timeout(1000, E.T, async () =>
await quick())`. Under `ceesafec 0.15.1` it crashes (SIGSEGV) or hangs in 4 runs of 4, and never prints `ok`.

The mail server showed it as:
- **Relay workers stalling:** each still held its queue claim, and the queue stopped draining. It happened in 3 of 5
  runs of 300 messages (4 workers on one thread), and in every run of 1,000 messages with the default settings.
- **Aborts:** `ceesafe: a task waits on a descriptor and a wake at once`.
- **A task dump with a loop in the ready queue:** `ceesafe_async_dump()` listed the same relay worker as "ready" 199
  times.

**Cause, in three steps:**
1. **The wake goes stale.** `ceesafe_async_blocking_finish` sets `done`, then wakes the task. If the task sees
   `done` first, the wake lands later anyway, and the task's `woken` stays set. Instrumenting `cee_wake_task` showed
   these wakes come from `blocking_finish`, arriving at tasks that were neither parked nor `on_wake`.
2. **The run loop treats it as real.** At the task's next suspension, `if (ceesafe_atomic_swap_u64(&t->woken, 0u) !=
   0u) { … cee_ready(t); }` readies it, whatever it registered. It clears `on_wake`, but leaves the task's other
   registrations in place:
   - `on_scope`, with `scope->waiter` still pointing at the task;
   - its `fd`;
   - its `deadline`.
3. **The leftovers do damage.**
   - **Stale scope waiter:** when a child returns, `cee_child_done` calls `cee_unpark(waiter)` on a task that is
     already queued. `cee_unpark` readies unconditionally, so the task is queued twice. As the tail, it then links
     to itself, which hangs the scheduler, or a finished embedded task runs again, which crashes it.
   - **Stale `fd`:** it reaches a later wait on a wake, which is the abort.

**Suggested fix** (`~/dev/CeeSafeLibs/repros/stale-wake/runtime-fix.patch`, which applies to CeeSafe HEAD 1b08b5a):
in the run loop, act on `woken` only when the task is `on_wake`. Every waker targets a task that registered `on_wake`
in that same resume: signal, blocking, shared scope, channel and DNS. Any other wake is stale and is dropped. When the
wake is real, also reset `deadline` and `fd`, as `cee_unpark` does.
- **Tested:** with that one change, the repro prints `ok` in 4 runs of 4. The mail server's relay load test passes:
  - 8 runs of 8 with 300 messages;
  - 3 runs of 3 with 1,000 messages over STARTTLS with the connection pool, against 0 of 2 unpatched.
- **Worth adding (untested):**
  - `cee_child_done` should unpark the waiter only if `waiter->parked`, and otherwise just clear `on_scope`. A ready
    task re-checks `scope_done` itself.
  - `cee_unpark` could assert `t->parked` in debug builds. A second readying is always a bug, and silent until the
    queue loops.

- **Workaround:** none in this code. `Async.blocking` has 32 call sites across msmtp, mqueue, mstore and main. The
  stale wake strikes at whatever suspension comes next, so no local change avoids it. The mail server needs a
  `ceesafec` with the fix.

---

## 2. Silent wrong behaviour: compiles, then misbehaves

These are the most dangerous items, because nothing tells the programmer.

### 2.1 ✔ A character literal is a `u32`, so `pushBE('P')` writes four bytes

```ceesafe
var v = Vector<u8>.create();
v.pushBE('P')!;   // v.length == 4
```

- This made a malformed Postgres message (`08P01 invalid message format`).
- `v.push('P')` is fine, because the expected type fixes the literal.
- **Workaround:** write `0x50u8`.
- **Fix:** reject an unsuffixed character literal where no width is fixed (as N0260 does for integers), or default
  it to `u8` in a byte context.

### 2.2 ✔ `"{x}"` is printed literally

```ceesafe
let x = 3;
Console.writeLine("x = {x}");   // prints: x = {x}
```

- C# and TypeScript habits make this easy to write.
- **Fix:** warn on `{identifier}` inside a literal (at least one passed to `Console.write*`), or add interpolation.

### 2.3 `Console.write` panics on text that is not UTF-8

- `Console.write(StringView.fromUtf8(bytes)!)` on mail data panics.
- **Workaround:** `Console.writeBytes`. It is documented but easy to miss.
- **Fix:** point to `writeBytes` from the `fromUtf8` docs, or have the panic message suggest it.

### 2.4 `ceesafec test` collects a dependency's `@test` functions, then cannot call them

- A library that keeps tests in `src/` breaks `ceesafec test` in every package that depends on it, with N0312
  ("… is not public").
- **Workaround:** tests in `tests/` with `tests = ["tests"]` in the manifest.
- **Fix:** collect tests only from the package being tested.

---

### 2.5 A package's C file builds on macOS and not on Linux (found in Phase 8, 0.18.2)

Building the server for Linux (the Docker image) failed in two CeeSafeLibs shims. Neither shows on macOS.

- **Headers left behind.** `tls/c/tls_shim.c` includes `"tls_shim.h"` from its own directory. On macOS the package
  has `[target.macos] include-dirs` (Homebrew's OpenSSL), so tooling.md §4.1 compiles its C files apart, and the
  header is found. On Linux it has none, so the `.c` is copied alone into the build's temporary directory, and the
  `#include` fails. A C file's quoted includes should resolve against its own directory whichever way it is
  compiled: copy the directory, or always pass `-I<the file's directory>`. Workaround: `[target.linux]
  include-dirs = ["c"]`.
- **Strict C hides POSIX.** `diskio/c/diskio_shim.c` uses `PATH_MAX` and `O_CLOEXEC`, which glibc declares only
  under a POSIX feature macro; the shim is compiled as strict ISO C. Fix in the shim: `#define _POSIX_C_SOURCE
  200809L`. Worth a line in the guide's page on C files: a hosted shim that calls POSIX should define it.

## 3. Language gaps, by how often they cost code

### 3.1 ✔ No `??`, and optionals have no methods

```ceesafe
let t = StringView.fromUtf8(b) ?? "fallback";   // N0100
x.isSome()                                      // N0234
```

- Every fallback is a four-line `match`.
- Helpers such as `orElse<T: Copy>` cannot take a `StringView` (N0274), so string getters need their own `textOr`.
- This is the most common friction in the port: every nullable database column and every header lookup hits it.
- **Fix:** add `??`, plus `isSome`, `isNull` and `valueOr` on optionals.

### 3.2 ✔ A temporary cannot be borrowed (N0247)

```ceesafe
fn make() -> String { … }
use(make().view());          // N0247: bind the value to a local first
```

- This happens constantly in tests and string building.
- **Fix:** extend a temporary's life to the end of the statement, as C++ and Rust do.

### 3.3 ✔ No two-phase borrows (N0242)

```ceesafe
fn fail(s: borrow mut S, line: u32) { … }
fail(mut s, s.n[0]);         // N0242: cannot use 's.n' while 's' is mutably borrowed
```

- **Workaround in msieve:** a separate `Problem` struct for validation errors, copied into the script at the end.
- A related case in PostgresClient: `run(connection, await connection.batch(sql))` is N0241.
- **Fix:** evaluate Copy arguments before the mutable borrow starts, as Rust's two-phase borrows do.

### 3.4 ✔ The loop variable's type ignores how it is used (N0205)

```ceesafe
fn take(n: usize) -> usize => n;
for (i in 0..3) { total += take(i); }          // N0205: expected 'usize', found 'i32'
for (i in 0..list.count()) { list.host(i); }   // same, though count() returns usize
```

- The range is `usize` only when the body *indexes* with `i`. This was hit three times in this port.
- **Workaround:** a `while` loop with `var i: usize`.
- **Fix:** make the range `usize` when either bound is `usize`, or when `i` is passed as a `usize` argument.

### 3.5 ✔ `==` is missing on slices, fieldless enums and arrays (N0207)

```ceesafe
"ab".bytes() == "ab".bytes()   // N0207 (StringView has ==; Slice<u8> does not)
k == K.A                       // N0207 for `enum K { A, B }`
[u8; 16] == [u8; 16]           // not allowed
```

- **Workarounds:**
  - for slices, `a.length == b.length && a.startsWith(b)` or a helper;
  - for enums, an `isX()` method per variant written with `match`;
  - for arrays, a loop over the elements.
- **Fix:**
  - content equality for `Slice<T: Eq>` and arrays;
  - derived equality for enums whose variants have no payloads.

### 3.6 ✔ Match arms cannot be blocks that give a value (N0100)

```ceesafe
let x = match (y) { Some(v) => { let w = v + 1; w } null => 0 };   // N0100
```

- **Workaround:** a `var` assigned in each arm, or a helper function.
- **Fix:** let a block's final expression be its value, in match arms at least.

### 3.7 ✔ A generic over `T` cannot be used with `void` (N0222)

```ceesafe
fn conv<T>(r: Result<T, A>) -> Result<T, B> => match (r) { Ok(v) => Ok(v), Err(_) => Err(B.Y) };
conv(act())   // act() -> Result<void, A>: 'Ok' has 0 payload values, but the pattern binds 1
```

- **Workaround:** a second, void-only adapter (msmtp has `oom` and `stored`; mqueue's `grown` is void-only).
- **Fix:** let `Ok(v)` bind the unit value when `T` is `void`.

### 3.8 ✔ No `let _ = …` (N0100)

- A result that must be bound but is not needed has to take a name (`let ignored = …`).
- **Fix:** accept `_` as a discard pattern.

### 3.9 Async children and timeouts cannot consume what they capture

- Task-set children own their captures but read them through their environment. So
  `async move () => await serve(stream)`, ADR 0053's own example, is N0251 for any non-Copy capture.
- `Async.timeout(ms, e, async () => await TlsStream.accept(stream, cfg))` cannot move `stream` in, for the same
  reason.
- **Workarounds:**
  - the value travels in a one-element `Vector` that the child `pop()`s;
  - tls gained `TlsStream.acceptWithin(stream, cfg, ms)`.
- **Fix:** let a closure move its captures out, so that `async move` and a moving `Async.timeout` work.

### 3.10 Regions and methods

- **A slice returned from a `borrow mut this` method stays borrowed from `this`.** A lexer's
  `fn token(borrow mut this) -> Slice<r, u8>` still holds the mutable loan, so the next `lexer.skipSpace()` is N0241.
  Lexers return offsets instead, and the caller slices.
- **Methods cannot declare region parameters** (N0216), and `borrow(this) Slice<u8>` is refused ("references to
  references"). Such methods become free functions: `fn findParam<region a>(p: borrow(a) ParamList, …) -> Slice<a, u8>?`.
- **Views cannot be `var`** (N0246, for a `StringView` or a `Slice` local, and `var name = "literal"`). A parser
  that narrows a view step by step keeps offsets instead; a choice between literals is one `let` with an `if`.
- **Fix:**
  - tie a result that names the struct's region to that region only, not to the `this` loan;
  - allow region parameters on methods;
  - consider re-pointable views (`var` of a view type).

### 3.11 Literals and constants

- **No multi-line string literals.** SQL lives in `.sql` files, and `tools/embed-sql.py` generates the `.cee`
  functions. The fix is raw or multi-line literals, or an `embed("file")` built-in (ADR 0064 finding A3 again).
- **A literal over 4095 bytes makes clang warn** (`-Woverlength-strings`). The fix is for the C backend to emit
  long literals as a `char[]` initializer, or as split pieces.
- ✔ **`.length` of a `const` array is N0216.** A 10,406-entry Public Suffix List table needs a separate
  `PSL_COUNT`. The fix is to allow `.length` on a const array; it is known at compile time.
- **Structs cannot hold `const`s** (N0107), so related constants become top-level `OID_…` names.

### 3.12 ✔ An optional field cannot be passed as an optional borrow

```ceesafe
fn f(c: borrow TlsConfig?) { … }
f(relay.tlsConfig);          // N0205: expected 'borrow tls.TlsConfig?', found 'tls.TlsConfig?'
f(borrow relay.tlsConfig);   // N0205: expected 'borrow tls.TlsConfig?', found 'borrow (tls.TlsConfig?)'
```

- `borrow T?` is an optional borrow, and there is no way to make one from a `T?` field without a `match` that builds
  it. This was met in the relay, which keeps an optional TLS configuration.
- **Workaround:** always hold a configuration, and pass a separate `useTls` flag.
- **Fix:** convert `borrow (T?)` to `borrow T?` implicitly, or add `opt.asBorrow()`.

### 3.13 ✔ `split` cannot be looped over with `for`

- `for (part in text.split(","))` is N0205: `for` takes arrays, slices and ranges; `TextSplit` has only `next()`.
- **Workaround:** `loop { match (parts.next()) { Some(p) => …, null => { break; } } }`.
- **Fix:** let `for` take any type with `next() -> T?`.

### 3.14 Conversions

- `as` is lossless only, so `usize` to `i64` needs `truncate<i64>(n)`. That reads as possibly lossy where it is not.
- **Fix:** allow `as` where the value range proves it safe, or add `i64.fromSize(n)`.

---

## 4. Names that collide

- **A dependency's name cannot be a local's** (N0315). A library called `files` broke every `let files = …` in the
  packages that depend on it, so it was renamed `diskio`. Met again in the relay: a parameter named `tls` (the
  natural name) collides with the `tls` package. Since a dependency is reached as `name.Item`, a local
  could shadow it with a warning instead.
- **Built-in names take user names silently, until they collide** (N0201): `Check` (from the test harness) and
  `Handle` (from `SlotMap`). The fix is a namespace for test helpers (`test.Check`) and fewer global built-ins.
- **Keywords that read like names:** `own`, `move`, `type`, `drop`, `where`, `null` (`params.null()` had to become
  `sqlNull()`), and `public` (a local holding a public key: hit twice in one slice). The N0100 message is clear; a list in the guide would save the guess.
- **A method cannot have a field's name.**

---

### 4.1 A function that exits is not known to

- `die()` (it calls `Process.exit`) still returns `void` to the checker. So `Err(_) => { die("…"); }` in a match
  that gives a value is N0235 ("this block can complete, but it has no value"), and a dead `return` has to follow.
- **Fix:** a never-returning type (`-> never`) for functions that always exit or panic, as `Process.exit` could
  declare.

## 5. Documentation

- **C calls in async code.** An `extern "C"` function without `@effects` counts as possibly sleeping, so calling it
  from async code is N0295. The fix is `@effects(alloc)` or `@effects()` on the declaration. Say so in the
  unsafe-and-C chapter, next to the async rule.
- **Small API surprises worth a line each:**
  - `AsyncMutexGuard.data()` is a method;
  - `Async.tasks` takes a `u32` limit;
  - `Console.writeBytes` is for bytes that are not UTF-8;
  - `Async.blocking` is required for every `sleep`-effect call (disk, bcrypt) in async code.

---

## 6. What worked well

- **The effect checker caught real bugs**, four times:
  - a `drop` that deleted a temporary file could not run in async code (a design bug);
  - it kept every disk, iconv and bcrypt call on `Async.blocking`;
  - it kept the MIME scanner pure;
  - it stopped console output (and a `die`) inside the async admin commands, which would have blocked a worker
    thread.
- **Allocation-failure testing:** a sweep of 1,042 runs injecting allocation failures into mmime found no crash and
  no leak; every failure reached the caller as `AllocError`.
- **Differential tests found only differences in meaning.** Against Dovecot (MIME, 4,010 checks), RFC 7208 (SPF, 203),
  dkimpy (DKIM, 78) and Pigeonhole (Sieve, 100), none showed a memory problem or a crash.
- **Async recursion** (SPF's `include` and `redirect`) just works.
- **`?` inside an `Async.blocking` closure** works.
- **Large modules passed check** with only the errors above: the 1,100-line Sieve evaluator and the 300-line
  vacation module.
- **Diagnostics are good:** most messages name the fix ("bind the value to a local first", "did you mean").

---

## Suggested order

Everything above is fixed in 0.18.0 except two items:

1. **Re-pointable `var` views (§3.10, N0246):** they need their own ADR, because assigning to a reference writes
   through it today.
2. **§2.3, `Console.write` on text that is not UTF-8:** a documentation fix, not re-tested.
