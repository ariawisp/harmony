# Harmony C bindings

Harmony ships with a minimal C-compatible ABI so that it can be consumed from
C, C++, Objective-C(++) and Swift. The entry points are defined in
[`include/openai_harmony.h`](../include/openai_harmony.h) and implemented in the
Rust crate.

## Building

The crate now emits both a dynamic library (`cdylib`) and a static archive
(`staticlib`). Use Cargo to build the flavour you need:

```bash
# macOS (Apple Silicon)
cargo build --release --target aarch64-apple-darwin

# iOS device (static only)
cargo build --release --target aarch64-apple-ios

# iOS simulator
cargo build --release --target aarch64-apple-ios-sim

# Linux
cargo build --release --target x86_64-unknown-linux-gnu

# Windows (dynamic library)
cargo build --release --target x86_64-pc-windows-msvc
```

The resulting library lives in `target/<triple>/release/` and can be linked
into your application directly or packaged inside an XCFramework for Xcode.

## Header + linking

Include `include/openai_harmony.h` in your project and link the produced
`libopenai_harmony.{a,dylib,so}` (or the `.dll`/import library on Windows).
All exported functions return a `HarmonyStatus` code. On success the status is
`HARMONY_STATUS_OK` and any output parameter is populated. On failure a
human-readable error message is returned via `char **out_error`; call
`harmony_string_free` on that pointer when you are done with it.

All heap-allocated outputs are owned by Rust. Free them using the companion
helpers (`harmony_owned_u32_array_free`, `harmony_owned_u8_array_free`,
`harmony_string_array_free`, `harmony_string_free`).

## Example (C)

```c
#include "openai_harmony.h"
#include <stdio.h>

int main(void) {
    HarmonyEncodingHandle *enc = NULL;
    char *error = NULL;
    HarmonyStatus status = harmony_encoding_new("harmony_gpt_oss", &enc, &error);
    if (status != HARMONY_STATUS_OK) {
        fprintf(stderr, "failed to load encoding: %s\n", error);
        harmony_string_free(error);
        return 1;
    }

    const char *conversation_json =
        "{\"messages\":[{\"author\":{\"role\":\"user\"},\"content\":[{\"text\":\"Hello\"}]}]}";
    HarmonyOwnedU32Array tokens;
    status = harmony_encoding_render_conversation(enc, conversation_json, NULL, &tokens, &error);
    if (status != HARMONY_STATUS_OK) {
        fprintf(stderr, "render failed: %s\n", error);
        harmony_string_free(error);
        harmony_encoding_free(enc);
        return 1;
    }

    printf("rendered %zu tokens\n", tokens.len);
    harmony_owned_u32_array_free(tokens);
    harmony_encoding_free(enc);
    return 0;
}
```

## Example (Swift)

1. Add the static or dynamic library to the "Link Binary With Libraries" build
   phase (or ship it as an XCFramework).
2. Add `openai_harmony.h` to your project and, for Swift targets, include it in
   a bridging header:

   ```objc
   // HarmonyBridging.h
   #include "openai_harmony.h"
   ```

3. Call the C API from Swift:

   ```swift
   import Foundation

   var encoder: UnsafeMutablePointer<HarmonyEncodingHandle>? = nil
   var error: UnsafeMutablePointer<CChar>? = nil
   if harmony_encoding_new("harmony_gpt_oss", &encoder, &error) != HARMONY_STATUS_OK {
       if let error = error { print("Failed: \(String(cString: error))") }
       harmony_string_free(error)
       exit(1)
   }
   defer { harmony_encoding_free(encoder) }

   var tokens = HarmonyOwnedU32Array(data: nil, len: 0)
   let convo = "{\"messages\":[]}"
   if harmony_encoding_render_conversation(encoder, convo, nil, &tokens, &error) == HARMONY_STATUS_OK {
       print("Token count: \(tokens.len)")
       harmony_owned_u32_array_free(tokens)
   }
   harmony_string_free(error)
   ```

Swift Package Manager users can package the static libraries inside an
XCFramework and declare it as a `.binaryTarget` so that importing
`openai_harmony` exposes the same symbols.

## Notes

- All strings passed into the API must be UTF-8.
- Panics on the Rust side are caught and surfaced as
  `HARMONY_STATUS_PANIC` with an explanatory error string.
- Complex structures (conversations, messages) are exchanged via JSON to keep
  the ABI surface small. Reuse the existing Python dataclasses or mirror the
  Rust structures when producing that JSON.

