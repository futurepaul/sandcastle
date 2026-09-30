# sandcastle-web

A browser's way to a sandcastle computer by its key (fragment-next
`docs/runtime-seam.md`): a throwaway iroh key, a connection through the
computer's relay, an admission, then HTTP and WebSockets over iroh
streams, as `sandcastled --iroh-relay` serves them. On the host the crate
is empty; it is built for `wasm32-unknown-unknown` only.

`page/index.html` is the e2e's test page: it does what a chat page does
(a first answer, awake requests, warm and cold wakes, Hermes' login, its
socket, and a turn) and reports the times to the e2e's `web` section.

## Building

`ring` compiles C for wasm, which Apple's clang cannot; an unwrapped LLVM
clang can, pointed at its own headers. `wasm-bindgen` must be the version
`Cargo.lock` pins (0.2.127).

```sh
clang=$(nix build --no-link --print-out-paths nixpkgs#llvmPackages_19.clang-unwrapped)
lib=$(nix build --no-link --print-out-paths nixpkgs#llvmPackages_19.clang-unwrapped.lib)
llvm=$(nix build --no-link --print-out-paths nixpkgs#llvmPackages_19.llvm)
export CC_wasm32_unknown_unknown=$clang/bin/clang AR_wasm32_unknown_unknown=$llvm/bin/llvm-ar
export CFLAGS_wasm32_unknown_unknown="-resource-dir $lib/lib/clang/19"
RUSTFLAGS='--cfg getrandom_backend="wasm_js"' cargo build --release --target wasm32-unknown-unknown -p sandcastle-web
cargo install wasm-bindgen-cli --version 0.2.127 --locked
rm -rf target/web && mkdir -p target/web
wasm-bindgen target/wasm32-unknown-unknown/release/sandcastle_web.wasm --target web --out-dir target/web/pkg --out-name sandcastle_web
cp crates/web/page/index.html target/web/
```

Then the e2e with `--hermes --web target/web` opens it in headless Chrome
(`CHROME_BIN`, or Chrome's default place on macOS).

Measured 2026-09-30: the module is 3.97 MB raw, 1.43 MB gzipped, 1.01 MB
with brotli (`wasm-opt -Oz` saves raw bytes, not compressed ones).
