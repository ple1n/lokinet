# Embedding Lokinet into an existing application

The `lokinet-embedded` Nix package builds the shared Lokinet client library and
installs its `lokinet-embedded.pc` pkg-config file. The `rs-lokinet` Rust crate
provides an owned runtime handle for starting, checking, and stopping a client.

Build both packages with Nix:

```sh
nix build .#lokinet-embedded
nix build .#rs-lokinet
```

In another Cargo package, depend on the Rust wrapper and enable pkg-config to
find the library:

```toml
[dependencies]
rs-lokinet = { path = "rust/rs-lokinet" }
```

The caller supplies the Lokinet INI contents and an absolute data directory:

```rust,no_run
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = rs_lokinet::Config::new(
        String::new(),
        std::path::PathBuf::from("/var/lib/lokinet"),
    );
    let runtime = rs_lokinet::Runtime::start(config)?;
    let connected = runtime.is_connected();
    drop(runtime);
    let _ = connected;
    Ok(())
}
```

Dropping `Runtime` stops Lokinet and waits for its worker thread to finish.
This wrapper manages the embedded client lifecycle; it does not accept or own a
TUN file descriptor.
