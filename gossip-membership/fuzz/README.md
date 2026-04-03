# Fuzz Testing

Property-based fuzz tests for the gossip wire protocol using
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer).

## Targets

| Target | What it fuzzes |
|---|---|
| `fuzz_message_decode` | `Message::decode` — arbitrary bytes into the full message decoder. Verifies no panics, checksum rejection, version gating, and encode/decode roundtrip on valid inputs. |
| `fuzz_wire_node_entry_decode` | `WireNodeEntry::decode` — arbitrary bytes into the membership entry decoder. Verifies no panics, length bounds, and encode/decode roundtrip on valid inputs. |

## Prerequisites

```bash
# Install cargo-fuzz (one-time)
cargo install cargo-fuzz

# Nightly toolchain required
rustup toolchain install nightly
```

## Running locally

```bash
# Run a specific target for 60 seconds
cargo +nightly fuzz run fuzz_message_decode -- -max_total_time=60

# Run with more parallelism (4 jobs)
cargo +nightly fuzz run fuzz_message_decode -- -max_total_time=60 -jobs=4 -workers=4

# Run all targets for 30 seconds each
for target in fuzz_message_decode fuzz_wire_node_entry_decode; do
    echo "=== $target ==="
    cargo +nightly fuzz run "$target" -- -max_total_time=30
done
```

## Corpus

The fuzzer builds a corpus of interesting inputs in `fuzz/corpus/<target>/`.
These are checked in and reused across runs. To minimize the corpus:

```bash
cargo +nightly fuzz cmin fuzz_message_decode
```

## CI

The GitHub Actions workflow (`.github/workflows/fuzz.yml`) runs each target
for 30 seconds on every push/PR and nightly for extended coverage.

## Crashes

If the fuzzer finds a crash, it writes the input to `fuzz/artifacts/<target>/`.
To reproduce:

```bash
cargo +nightly fuzz run fuzz_message_decode fuzz/artifacts/fuzz_message_decode/crash-...
```
