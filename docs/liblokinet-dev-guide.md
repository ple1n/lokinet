# Embedding Lokinet into an existing application

The `lokinet-embedded` Nix package builds the shared Lokinet client library and
installs its `lokinet-embedded.pc` pkg-config file. The `rs-lokinet` Rust crate
provides an owned runtime handle and UDP/TCP flow APIs.

Build both packages with Nix:

```sh
nix build path:./#lokinet-embedded
nix build path:./#rs-lokinet
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

`Runtime::bind_udp` creates an inbound UDP endpoint. Its filter callback accepts
or rejects each remote flow and supplies a nonzero timeout; receive and timeout
callbacks are invoked as packets arrive and flows expire. The returned
`UdpSocket` can also establish outbound flows and send packets on them.
Closing a `UdpSocket` removes its endpoint handler and waits for in-flight
callbacks to finish before releasing callback storage; a duplicate exposed
port is reported as a bind error.

`Runtime::open_tcp_stream` creates an outbound Lokinet stream and returns its
local address and port. Connect a normal TCP socket to that local endpoint to
exchange data. `Runtime::listen_tcp_stream` registers an inbound stream filter;
accepted streams are mapped to `127.0.0.1:<remote-port>`, where the application
must have a local TCP listener. Dropping either TCP handle closes its Lokinet
stream.

Runtime and connection handles share ownership of the native context. Lokinet
stops and joins its worker thread when the last runtime, UDP socket, or TCP
stream/listener handle is dropped. The TCP API maps streams to local sockets
rather than exposing raw byte callbacks. Native calls are synchronous and may
block while crossing to Lokinet's event loop; invoke them off async executor
threads.
