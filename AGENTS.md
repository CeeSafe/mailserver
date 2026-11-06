<!--CEESAFE START-->

# Using CeeSafe

This package is written in CeeSafe, a memory-safe systems programming language with C#/TypeScript-style syntax that
`ceesafec` compiles ahead of time to C. Ownership and borrowing are checked at compile time; there is no garbage
collector. CeeSafe is new: code that looks right from C#, TypeScript or Rust often is not CeeSafe. Check every edit with the
compiler, and read the guide for agents: https://ceesafe.github.io/CeeSafe/guide/for-agents (the whole guide and
specification for a model's context: https://ceesafe.github.io/CeeSafe/llms-full.txt).

## The package

- `ceesafe.toml` names the package, its kind (`executable` or `library`) and its dependencies; `ceesafe.lock` pins them.
- The sources are the `.cee` files under `src/`. A program starts at `fn main()`.
- `ceesafec build` writes to `out/`, which is not committed.

## Commands

Run them in the package's directory; without file arguments they use the package.

| Command | What it does |
|---|---|
| `ceesafec check` | parse, type-check and borrow-check; the fastest way to find errors |
| `ceesafec fix` | apply the fixes the compiler is sure of, then check again |
| `ceesafec explain N0249` | what a diagnostic code means |
| `ceesafec run --interp` | run the program in the interpreter |
| `ceesafec build` | compile through C to `out/<name>` |
| `ceesafec fmt` | format in the one canonical style; `ceesafec fmt --check` lists files that would change |
| `ceesafec fetch` | resolve the dependencies and write `ceesafe.lock` |

Add `--diagnostics-format=json` to `check`, `build`, `run` or `fix` for one JSON document with every diagnostic, its
position and its fixes.

## The MCP server

If you have the `ceesafe` MCP server (`ceesafec mcp`), use its tools: `ceesafe_check` after every edit, `ceesafe_fix` for the
fixes it offers, `ceesafe_explain` for a code, `ceesafe_spec_search` and `ceesafe_spec_section` for the rules, `ceesafe_run` to
run code in a sandbox. The specification is embedded in `ceesafec`, so its answers match the compiler.

## Before you finish

- [ ] `ceesafec check` reports no errors (run `ceesafec fix` first).
- [ ] `ceesafec fmt --check` lists no file.
- [ ] The program does what was asked: `ceesafec run --interp`, or `ceesafec build` and run it.

## Common mistakes

- There is no `~`: complement with `x ^ 0xFFFFFFFF`. There are no type aliases, tuples or `==` on arrays.
- Indexes are `usize`. `0..4` is a `usize` range when the body indexes with its variable, else `i32`; `0..values.length` is `usize`.
- `if` and `match` expressions take expressions, not blocks: `let s = if (x < 0) -1 else 1;`.
- A variable that changes is `var`; a `let` cannot be assigned. A `borrow mut` argument is written `mut x`.
- `as` converts only without loss; `truncate<u8>(x)` wraps.
- Bind a constant or a temporary to a local before slicing it or asking its `.length`.
- Pass a function or closure as a parameter and call the parameter; a field holding one cannot be called.
- A `StringView` inside an enum or struct needs a region parameter; for fixed messages, use an enum of reasons.
- A method cannot have the name of a field.
- Look a name up before deciding it does not exist: MCP `ceesafe_api` (`TextWriter.decimal`, `Process.argument`), or
  the guide's built-in types page and the lib/core and lib/std API pages. A "did you mean" in an error names the real one.
- A lookup that may find nothing is an optional (`Process.argument(i)`, `StringView.fromUtf8(b)`): `Some`/`null`.
- Some keywords read like names (`own`, `type`, `move`, `drop`, `where`); async code uses `AsyncConsole`, not `Console`.

<!--CEESAFE END-->
