# cross-diff: Zig vs Rust byte-a-byte comparison

This tool validates that the Rust implementation produces identical output to the Zig implementation for all codec operations.

## How it works

1. Generate test vectors using the Zig implementation
2. Parse the same vectors using the Rust implementation
3. Compare byte-by-byte

## Usage

```bash
cd tools/cross-diff
cargo run --release
```

## Expected result

All vectors must match byte-for-byte. Any divergence indicates a bug in one of the implementations.
