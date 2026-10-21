use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

#[cfg(target_os = "linux")]
use rustix::{
    net::sockopt::set_socket_linger,
    process::{Pid, Resource, Rlimit, Signal, WaitOptions, kill_process, prlimit, waitpid},
};

const INTERFACE: [u8; 16] = [
    0x75, 0x21, 0xc8, 0x51, 0x4e, 0x84, 0x50, 0x47, 0xb0, 0xd8, 0xec, 0x25, 0x55, 0x55, 0xbc, 0x06,
];
const NDR32: [u8; 16] = [
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
];
const NDR64: [u8; 16] = [
    0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36,
];
const BTFN: [u8; 16] = [
    0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 3, 0, 0, 0, 0, 0, 0, 0,
];
const REQUEST: &[u8] = include_bytes!("fixtures/v4-request.bin");
const RESPONSE: &[u8] = include_bytes!("fixtures/v4-response.bin");

#[test]
fn negotiates_ndr64_and_ndr32_with_alter_context_and_reuses_connection() {
    let server = Server::start("");
    let mut stream = server.connect();
    let mut bind = bind_packet(11, &[(7, NDR32, 2), (9, NDR64, 1), (11, BTFN, 1)]);
    bind[16..18].copy_from_slice(&384_u16.to_le_bytes());
    bind[18..20].copy_from_slice(&512_u16.to_le_bytes());
    // A partial TCP write is not a fragmented RPC packet.
    stream.write_all(&bind[..9]).unwrap();
    stream.write_all(&bind[9..]).unwrap();
    let ack = read_packet(&mut stream);
    assert_eq!(ack[2], 12);
    let results = bind_results(&ack);
    assert_eq!(results, [(2, 2), (0, 0), (3, 3)]);
    assert_eq!(u32_at(&ack, 12), 1);

    for (context, limit) in [(7, 0_u16), (8, 16)] {
        let mut alter = bind_packet(14, &[(context, NDR32, 2)]);
        // AlterContext's fragment fields are ignored, including zero values.
        alter[16..18].copy_from_slice(&limit.to_le_bytes());
        alter[18..20].copy_from_slice(&limit.to_le_bytes());
        stream.write_all(&alter).unwrap();
        let ack = read_packet(&mut stream);
        assert_eq!(ack[2], 15);
        assert_eq!(bind_results(&ack), [(0, 0)]);
        assert_eq!(u16_at(&ack, 16), 512);
        assert_eq!(u16_at(&ack, 18), 384);
    }

    // Both requests arrive in one write and use independently negotiated contexts.
    let mut requests = activation(7, false, 20, REQUEST);
    requests.extend_from_slice(&activation(9, true, 21, REQUEST));
    stream.write_all(&requests).unwrap();
    for (call, context, ndr64) in [(20, 7, false), (21, 9, true)] {
        let response = read_packet(&mut stream);
        assert_eq!(u32_at(&response, 12), call);
        assert_eq!(u16_at(&response, 20), context);
        assert_eq!(response_data(&response, ndr64), RESPONSE);
    }

    let mut oversized = activation(7, false, 22, REQUEST);
    oversized.resize(385, 0);
    oversized[8..10].copy_from_slice(&385_u16.to_le_bytes());
    stream.write_all(&oversized).unwrap();
    assert_connection_closed(&mut stream);
}

#[cfg(target_os = "linux")]
#[test]
fn reset_connections_waiting_for_accept_do_not_stop_the_server() {
    let server = Server::start("");
    let pid = Pid::from_raw(server.child.id() as i32).unwrap();
    kill_process(pid, Signal::STOP).unwrap();
    let (_, status) = waitpid(Some(pid), WaitOptions::UNTRACED).unwrap().unwrap();
    assert!(status.stopped());
    // Queue resets before accept runs, avoiding a timing-dependent peer_addr race.
    for _ in 0..2 {
        let stream = server.connect();
        set_socket_linger(&stream, Some(Duration::ZERO)).unwrap();
        drop(stream);
    }
    kill_process(pid, Signal::CONT).unwrap();
    let mut stream = server.connect();
    stream
        .write_all(&bind_packet(11, &[(0, NDR32, 2)]))
        .unwrap();
    assert_eq!(bind_results(&read_packet(&mut stream)), [(0, 0)]);
    stream.write_all(&activation(0, false, 2, REQUEST)).unwrap();
    assert_eq!(response_data(&read_packet(&mut stream), false), RESPONSE);
}

#[cfg(target_os = "linux")]
#[test]
fn descriptor_exhaustion_preserves_clients_and_recovers_after_release() {
    let mut server = Server::start("");
    let pid = Pid::from_raw(server.child.id() as i32).unwrap();
    prlimit(
        Some(pid),
        Resource::Nofile,
        Rlimit {
            current: Some(32),
            maximum: Some(32),
        },
    )
    .unwrap();
    let mut active = server.connect();
    active
        .write_all(&bind_packet(11, &[(0, NDR32, 2)]))
        .unwrap();
    read_packet(&mut active);

    let clients: Vec<_> = (0..40).map(|_| server.connect()).collect();
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        assert!(
            server.child.try_wait().unwrap().is_none(),
            "server exited under descriptor pressure"
        );
        if fs::read_to_string(&server.stderr)
            .unwrap()
            .contains("(os error 24)")
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "EMFILE was not reached"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    active.write_all(&activation(0, false, 2, REQUEST)).unwrap();
    assert_eq!(response_data(&read_packet(&mut active), false), RESPONSE);

    drop(clients);
    let mut recovered = server.connect();
    recovered
        .write_all(&bind_packet(11, &[(0, NDR32, 2)]))
        .unwrap();
    assert_eq!(bind_results(&read_packet(&mut recovered)), [(0, 0)]);
    recovered
        .write_all(&activation(0, false, 2, REQUEST))
        .unwrap();
    assert_eq!(response_data(&read_packet(&mut recovered), false), RESPONSE);
}

#[test]
fn protocol_errors_leave_the_connection_and_other_clients_usable() {
    let server = Server::start("");
    let mut idle = server.connect();
    idle.write_all(&[5]).unwrap();

    let mut stream = server.connect();
    stream
        .write_all(&bind_packet(11, &[(3, NDR32, 2)]))
        .unwrap();
    assert_eq!(bind_results(&read_packet(&mut stream)), [(0, 0)]);

    stream
        .write_all(&activation(99, false, 2, REQUEST))
        .unwrap();
    let fault = read_packet(&mut stream);
    assert_eq!(fault[2], 3);
    assert_eq!(u32_at(&fault, 12), 2);
    assert_eq!(u16_at(&fault, 20), 99);
    assert_eq!(u32_at(&fault, 24), 0x1c01_0003);

    let mut bad_operation = activation(3, false, 3, REQUEST);
    bad_operation[22..24].copy_from_slice(&1_u16.to_le_bytes());
    stream.write_all(&bad_operation).unwrap();
    assert_eq!(u32_at(&read_packet(&mut stream), 24), 0x1c01_0002);

    let mut bad_version = REQUEST.to_vec();
    bad_version[2] = 7;
    let mut bad_length = activation(3, false, 5, REQUEST);
    bad_length[24..32].fill(0xff);
    for request in [activation(3, false, 4, &bad_version), bad_length] {
        stream.write_all(&request).unwrap();
        let response = read_packet(&mut stream);
        assert_eq!(response[2], 2);
        assert_eq!(u32_at(&response, 24), 0);
        assert_eq!(u32_at(&response, 28), 0);
        assert_eq!(u32_at(&response, 32), 0x8007_000d);
    }

    stream.write_all(&activation(3, false, 6, REQUEST)).unwrap();
    assert_eq!(response_data(&read_packet(&mut stream), false), RESPONSE);
}

#[test]
fn malformed_and_truncated_frames_only_close_their_own_connection() {
    let server = Server::start("");
    let mut malformed = packet(11, 1, &[]);
    malformed[8..10].copy_from_slice(&15_u16.to_le_bytes());
    let truncated = bind_packet(11, &[(0, NDR32, 2)]);
    for bytes in [&malformed[..], &truncated[..20]] {
        let mut stream = server.connect();
        stream.write_all(bytes).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        assert_connection_closed(&mut stream);
    }
    let mut stream = server.connect();
    stream
        .write_all(&bind_packet(11, &[(0, NDR32, 2)]))
        .unwrap();
    assert_eq!(bind_results(&read_packet(&mut stream)), [(0, 0)]);
    stream.write_all(&activation(0, false, 2, REQUEST)).unwrap();
    assert_eq!(response_data(&read_packet(&mut stream), false), RESPONSE);
}

#[test]
fn toml_overrides_are_reflected_in_activation_responses() {
    let server = Server::start(
        "activation_interval_minutes = 30\nrenewal_interval_minutes = 1440\n[epids]\nwindows = 'test-server'\noffice2016 = 'office-server'\n",
    );
    let mut stream = server.connect();
    stream
        .write_all(&bind_packet(11, &[(0, NDR32, 2)]))
        .unwrap();
    read_packet(&mut stream);
    let mut office = REQUEST.to_vec();
    office[48..64].copy_from_slice(&[
        0x1b, 0xf6, 0xb5, 0x85, 0x0b, 0x32, 0xe3, 0x4b, 0x81, 0x4a, 0xb7, 0x6b, 0x2b, 0xfa, 0xfc,
        0x82,
    ]);
    for (request, epid) in [(REQUEST, "test-server"), (&office[..], "office-server")] {
        stream.write_all(&activation(0, false, 2, request)).unwrap();
        let packet = read_packet(&mut stream);
        let data = response_data(&packet, false);
        let pid_size = u32_at(data, 4) as usize;
        let units: Vec<u16> = data[8..8 + pid_size - 2]
            .chunks_exact(2)
            .map(|bytes| u16::from_le_bytes(bytes.try_into().unwrap()))
            .collect();
        assert_eq!(String::from_utf16(&units).unwrap(), epid);
        assert_eq!(u32_at(data, 36 + pid_size), 30);
        assert_eq!(u32_at(data, 40 + pid_size), 1440);
    }
}

#[test]
fn whitelist_requires_both_hostname_and_peer_ip_for_all_kms_versions() {
    let requests: [(&[u8], bool); 3] = [
        (REQUEST, false),
        (include_bytes!("fixtures/v5-request.bin"), false),
        (include_bytes!("fixtures/v6-request.bin"), true),
    ];
    for (hostnames, ips, allowed) in [
        (
            "['^other$', '(?i)^KMS-TEST\\.EXAMPLE$']",
            "['^192\\.0\\.2\\.1$', '^127\\.0\\.0\\.1$']",
            true,
        ),
        ("['^other$']", "['^127\\.0\\.0\\.1$']", false),
        ("['^kms-test\\.example$']", "['^192\\.0\\.2\\.1$']", false),
    ] {
        let server = Server::start_with_config(&format!(
            "[whitelist]\nenable = true\nhostnames = {hostnames}\nips = {ips}\n"
        ));
        for (request, ndr64) in requests {
            let mut stream = server.connect();
            let syntax = if ndr64 { (NDR64, 1) } else { (NDR32, 2) };
            stream
                .write_all(&bind_packet(11, &[(0, syntax.0, syntax.1)]))
                .unwrap();
            assert_eq!(bind_results(&read_packet(&mut stream)), [(0, 0)]);
            stream.write_all(&activation(0, ndr64, 2, request)).unwrap();
            let response = read_packet(&mut stream);
            if allowed {
                let data = response_data(&response, ndr64);
                assert_eq!(&data[..4], &request[..4]);
            } else {
                assert_access_denied(&response, ndr64);
            }
        }
    }
}

#[test]
fn enabled_whitelist_with_empty_or_missing_lists_denies_activation() {
    for config in [
        "[whitelist]\nenable = true\n",
        "[whitelist]\nenable = true\nhostnames = ['.*']\nips = []\n",
        "[whitelist]\nenable = true\nips = ['.*']\n",
    ] {
        let server = Server::start_with_config(config);
        let mut stream = server.connect();
        stream
            .write_all(&bind_packet(11, &[(0, NDR32, 2)]))
            .unwrap();
        read_packet(&mut stream);
        stream.write_all(&activation(0, false, 2, REQUEST)).unwrap();
        assert_access_denied(&read_packet(&mut stream), false);
    }
}

#[test]
fn whitelist_is_bypassed_unless_explicitly_enabled() {
    for config in [
        "",
        "[whitelist]\nenable = false\nhostnames = ['^other$']\nips = ['^192\\.0\\.2\\.1$']\n",
        "[whitelist]\nhostnames = ['^other$']\nips = ['^192\\.0\\.2\\.1$']\n",
    ] {
        let server = Server::start_with_config(config);
        let mut stream = server.connect();
        stream
            .write_all(&bind_packet(11, &[(0, NDR32, 2)]))
            .unwrap();
        read_packet(&mut stream);
        stream.write_all(&activation(0, false, 2, REQUEST)).unwrap();
        assert_eq!(response_data(&read_packet(&mut stream), false), RESPONSE);
    }
}

#[test]
fn hostname_is_checked_again_for_each_request_on_a_connection() {
    let server = Server::start("");
    let mut stream = server.connect();
    stream
        .write_all(&bind_packet(11, &[(0, NDR32, 2)]))
        .unwrap();
    read_packet(&mut stream);
    let mut denied = REQUEST.to_vec();
    denied[108..236].fill(0);
    for (index, unit) in "kms-test.example.evil".encode_utf16().enumerate() {
        denied[108 + index * 2..110 + index * 2].copy_from_slice(&unit.to_le_bytes());
    }
    for (request, allowed) in [(REQUEST, true), (&denied[..], false), (REQUEST, true)] {
        stream.write_all(&activation(0, false, 2, request)).unwrap();
        let response = read_packet(&mut stream);
        if allowed {
            assert_eq!(response_data(&response, false), RESPONSE);
        } else {
            assert_access_denied(&response, false);
        }
    }
}

struct Server {
    child: Child,
    config: PathBuf,
    stderr: PathBuf,
    address: SocketAddr,
}

impl Server {
    fn start(settings: &str) -> Self {
        Self::start_with_config(&format!(
            "{settings}\n[whitelist]\nenable = true\nhostnames = ['^kms-test\\.example$']\nips = ['^127\\.0\\.0\\.1$']\n"
        ))
    }

    fn start_with_config(settings: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let config = std::env::temp_dir().join(format!(
            "vlmcsd-rs-test-{}-{}.toml",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&config, format!("listen = '127.0.0.1:0'\n{settings}")).unwrap();
        let stderr = config.with_extension("stderr");
        let child = Command::new(env!("CARGO_BIN_EXE_vlmcsd-rs"))
            .arg("--config")
            .arg(&config)
            .stdout(Stdio::piped())
            .stderr(fs::File::create(&stderr).unwrap())
            .spawn()
            .unwrap();
        let mut server = Self {
            child,
            config,
            stderr,
            address: "127.0.0.1:0".parse().unwrap(),
        };
        let stdout = server.child.stdout.take().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = BufReader::new(stdout).read_line(&mut line);
            let _ = sender.send(line);
        });
        let line = receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("server did not start");
        server.address = line
            .trim()
            .strip_prefix("Listening on ")
            .expect("server startup failed")
            .parse()
            .unwrap();
        server
    }

    fn connect(&self) -> TcpStream {
        let stream = TcpStream::connect_timeout(&self.address, Duration::from_secs(3)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.config);
        let _ = fs::remove_file(&self.stderr);
    }
}

fn packet(kind: u8, call: u32, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![5, 0, kind, 3, 0x10, 0, 0, 0];
    bytes.extend_from_slice(&((body.len() + 16) as u16).to_le_bytes());
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(&call.to_le_bytes());
    bytes.extend_from_slice(body);
    bytes
}

fn bind_packet(kind: u8, contexts: &[(u16, [u8; 16], u32)]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&5840_u16.to_le_bytes());
    body.extend_from_slice(&5840_u16.to_le_bytes());
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.extend_from_slice(&(contexts.len() as u32).to_le_bytes());
    for (id, syntax, version) in contexts {
        body.extend_from_slice(&id.to_le_bytes());
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&INTERFACE);
        body.extend_from_slice(&1_u32.to_le_bytes());
        body.extend_from_slice(syntax);
        body.extend_from_slice(&version.to_le_bytes());
    }
    packet(kind, 1, &body)
}

fn activation(context: u16, ndr64: bool, call: u32, request: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&((request.len() + if ndr64 { 16 } else { 8 }) as u32).to_le_bytes());
    body.extend_from_slice(&context.to_le_bytes());
    body.extend_from_slice(&0_u16.to_le_bytes());
    body.extend_from_slice(&(request.len() as u32).to_le_bytes());
    if ndr64 {
        // requestSize is still 32-bit; the padding before the array may be nonzero.
        body.extend_from_slice(&[0xa5; 4]);
        body.extend_from_slice(&(request.len() as u64).to_le_bytes());
    } else {
        body.extend_from_slice(&(request.len() as u32).to_le_bytes());
    }
    body.extend_from_slice(request);
    packet(0, call, &body)
}

fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
    let mut header = [0; 16];
    stream.read_exact(&mut header).unwrap();
    let mut packet = header.to_vec();
    packet.resize(usize::from(u16_at(&header, 8)), 0);
    stream.read_exact(&mut packet[16..]).unwrap();
    packet
}

fn assert_connection_closed(stream: &mut TcpStream) {
    let result = stream.read(&mut [0; 1]);
    assert!(
        matches!(result, Ok(0))
            || result.is_err_and(|error| matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            ))
    );
}

fn bind_results(packet: &[u8]) -> Vec<(u16, u16)> {
    let count_offset = (26 + usize::from(u16_at(packet, 24))).next_multiple_of(4);
    let count = u32_at(packet, count_offset) as usize;
    (0..count)
        .map(|index| {
            let offset = count_offset + 4 + index * 24;
            (u16_at(packet, offset), u16_at(packet, offset + 2))
        })
        .collect()
}

fn response_data(packet: &[u8], ndr64: bool) -> &[u8] {
    assert_eq!(packet[2], 2);
    let offset = if ndr64 { 48 } else { 36 };
    let size = u32_at(packet, 24) as usize;
    assert_eq!(u32_at(packet, offset + size), 0);
    &packet[offset..offset + size]
}

fn assert_access_denied(packet: &[u8], ndr64: bool) {
    assert_eq!(packet[2], 2);
    let status_offset = if ndr64 { 40 } else { 32 };
    assert!(packet[24..status_offset].iter().all(|byte| *byte == 0));
    assert_eq!(u32_at(packet, status_offset), 0x8007_0005);
    assert_eq!(packet.len(), status_offset + 4);
}

fn u16_at(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
}

fn u32_at(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}
