# vlmcsd-rs

A Rust KMS activation server emulator built with security in mind, supporting KMS protocol versions 4.0, 5.0, and 6.0, based on [vlmcsd](https://github.com/Wind4/vlmcsd).

The RPC implementation, KMS message encoding, and protocol-specific ciphers are written in Rust. SHA-256 and HMAC use RustCrypto. The server does not link to or invoke the C version of vlmcsd; third-party dependencies may use FFI internally.

## Build and run

Requires Cargo and Rust 1.96.0. When using rustup, the project's toolchain file selects this version.

```sh
cargo build --release --locked
./target/release/vlmcsd-rs --config ./vlmcsd.toml
```

Without `--config`, the server reads `vlmcsd.toml` from the current directory. A missing, unreadable, or invalid configuration file causes startup to fail. `--help` and `--version` are also available.

The server runs in the foreground. Startup messages, connection errors, and activation decisions go to standard output or standard error. Activation logs include the decoded hostname, TCP source IP, and whether the request was allowed or denied. Press Ctrl-C to stop the server.

## Configuration

Configuration is loaded at startup; restart the server after making changes. Omitted fields use built-in defaults, and unknown fields are rejected. Whitelist filtering is disabled in the example configuration. To enable it, add hostname and IP patterns and set `whitelist.enable = true`.

| Field | Default | Description |
| --- | --- | --- |
| `listen` | `"0.0.0.0:1688"` | A single listening address and TCP port. IPv6 example: `"[::]:1688"`. |
| `hwid` | `"3A1C049600B60076"` | The 8-byte hardware ID returned in V6 responses, written as exactly 16 hexadecimal digits. |
| `activation_interval_minutes` | `120` | Retry interval after an unsuccessful activation, in minutes. |
| `renewal_interval_minutes` | `10080` | Activation renewal interval, in minutes. |
| `[epids]` | Upstream ePID defaults | Server product identifiers for each product group. |
| `whitelist.enable` | `false` | Enables whitelist filtering only when set to `true`. |
| `whitelist.hostnames` | `[]` | Hostname regular expressions. |
| `whitelist.ips` | `[]` | TCP source IP regular expressions. |

Both intervals must be positive 32-bit unsigned integers. An ePID must contain 1 to 63 UTF-16 code units and must not contain NUL. ePIDs remain fixed during operation and are not generated randomly.

The `[epids]` table supports `windows`, `win_china_gov`, `office2010`, `office2013`, `office2016`, and `office2019`. The request's KMS ID selects the product group. As in the reference implementation, unknown KMS IDs use the `windows` group; product names and SKU IDs are not used to reject requests. You can omit the entire table to use the built-in ePIDs.

For example, allow only clients connecting from localhost and reporting the hostname `pc-01.example.local`, while keeping the default response parameters:

```toml
listen = "127.0.0.1:1688"
hwid = "0123456789ABCDEF"

[whitelist]
enable = true
hostnames = ['(?i)^pc-01\.example\.local$']
ips = ['^127\.0\.0\.1$']
```

## Regex whitelist

Filtering runs only when `enable = true`. Setting it to `false` or omitting it bypasses whitelist filtering, even if configured patterns do not match.

When enabled, **both the hostname and the source IP must match** at least one pattern in their respective lists. An empty or missing list denies activation. To restrict only one field, explicitly set the other list to `['.*']`.

```toml
[whitelist]
enable = true
hostnames = ['(?i)^pc-[0-9]+\.example\.local$', '^BUILD-SERVER$']
ips = ['^192\.168\.10\.[0-9]{1,3}$', '^127\.0\.0\.1$', '^::1$']
```

- Patterns use Rust [regex](https://docs.rs/regex/) syntax. Matching is case-sensitive by default; use `(?i)` to ignore case. Patterns can match substrings unless anchored with `^` and `$`. TOML single-quoted strings preserve backslashes and are convenient for regex patterns.
- Patterns are compiled and validated when loading the configuration. Invalid patterns prevent startup, even when filtering is disabled.
- Hostnames are decoded from the V4/V5/V6 `WorkstationName` field as UTF-16LE, ending at the first NUL. Invalid UTF-16 produces an invalid-data error.
- IPs come from the actual TCP connection, without a port or brackets. No DNS lookup is performed. IPv6 addresses use their standard compressed representation. IPv4-mapped addresses such as `::ffff:192.0.2.10` are matched as `192.0.2.10`.
- When filtering is enabled, every activation request is checked, including requests that reuse a TCP connection. A rejected request returns `0x80070005` ([E_ACCESSDENIED](https://learn.microsoft.com/en-us/windows/win32/seccrypto/common-hresult-values)) without activation data.

The hostname is supplied by the client and is not an authenticated identity. The source IP is the address visible to the server, which may differ from the client's local address when NAT or container port forwarding is involved. Use the IP shown in activation logs when configuring rules.

## Docker

The Dockerfile builds a static executable using Rust 1.96 on Alpine. The final image uses scratch and runs as UID/GID `65532:65532`. It includes the license at `/usr/share/licenses/vlmcsd-rs/LICENSE`.

```sh
docker compose up -d --build
docker compose logs -f
docker compose down
```

Compose publishes TCP port 1688, mounts the host's `vlmcsd.toml` read-only at `/etc/vlmcsd-rs/vlmcsd.toml`, and uses `restart: unless-stopped`. Run `docker compose restart` after editing the configuration. Use `0.0.0.0:1688` for `listen` inside the container so that port forwarding can reach the server. To change the host port, edit `ports` in the Compose file.

You can also build and run the image directly:

```sh
docker build -t vlmcsd-rs .
docker run --rm -p 1688:1688 \
  --mount type=bind,src="$(pwd)/vlmcsd.toml",dst=/etc/vlmcsd-rs/vlmcsd.toml,readonly \
  vlmcsd-rs
```

## Protocol support

- DCE/RPC Bind, AlterContext, NDR32, NDR64, and BTFN negotiation are supported. Bind and AlterContext requests may advertise `PFC_SUPPORT_HEADER_SIGN`; responses clear that capability bit.
- Multiple activation requests can share a connection. TCP segmentation and consecutive messages are handled. RPC fragment reassembly and RPC authentication are not supported.
- Each connection is handled by a separate thread with 30-second read and write timeouts. Connection resets during acceptance do not terminate the server. Accept errors are logged and retried after a 100 ms delay, allowing acceptance to recover when file descriptors become available.
- Client counting is stateless: responses return `max(1, 2 * N_Policy)`, where `N_Policy` is the client's required minimum count. A requested minimum above 1000 produces an invalid-data error.
- Responses echo the client ID and timestamp. The server does not maintain a client list or check client clock skew, and requires no database or persistent data directory.
- No activation client, service installer, or automatic discovery functionality is included.

Protocol support does not imply testing against every Windows or Office release. Interoperability checks use the upstream vlmcs client's protocol validation.

## Checks and tests

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo build --release --locked
docker compose config --quiet
```

Crypto and KMS unit tests compare V4/V5/V6 responses with fixed packets generated by the upstream implementation. They require neither a C compiler nor the upstream source tree. See the [fixture documentation](tests/fixtures/README.md) for provenance and generation parameters.

Network integration tests start the server on temporary ports. They cover RPC negotiation, nonzero NDR64 alignment padding, preservation of fragment limits across AlterContext, connection reuse, error isolation, configuration overrides, and whitelist filtering across all three KMS versions. Linux tests also exercise queued TCP resets and descriptor exhaustion, reducing only the test server child process's descriptor limit and checking continued service and recovery.

If the upstream vlmcs client is installed, allow `pc-01.example.local` and the actual source IP in the whitelist, then run these independent interoperability checks:

```sh
for version in 4 5 6; do
  for ndr64 in 0 1; do
    vlmcs "-$version" "-N$ndr64" -n2 -w pc-01.example.local -v 127.0.0.1:1688
  done
done
```

Check the output for `ERROR`, `WARNING`, or `Fatal` messages rather than relying only on the client's exit code. The upstream client is an external verification tool, not a project dependency.

## License

This project is licensed under the GNU Affero General Public License version 3 only (`AGPL-3.0-only`). See [LICENSE](LICENSE) for the full terms. Third-party dependencies retain their respective licenses.
