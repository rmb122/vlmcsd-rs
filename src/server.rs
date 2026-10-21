use std::{
    io::{self, Read, Write},
    net::{IpAddr, TcpListener, TcpStream},
    sync::Arc,
    thread,
    time::Duration,
};

use crate::{
    config::Config,
    kms::Service,
    rpc::{Header, Session},
};

pub fn run(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let address = config.listen;
    let service = Arc::new(Service::new(config)?);
    let listener = TcpListener::bind(address)?;
    let local_address = listener.local_addr()?;
    println!("Listening on {local_address}");
    io::stdout().flush()?;
    let mut association = 0_u32;
    loop {
        // accept supplies the peer address before a subsequent client reset can
        // make querying the accepted socket's peer fail.
        let (stream, peer) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                eprintln!("cannot accept connection: {error}");
                // Give transient network errors and resource exhaustion time to recover.
                thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        association = association.wrapping_add(1).max(1);
        let service = Arc::clone(&service);
        if let Err(error) = thread::Builder::new()
            .name(format!("kms-{peer}"))
            .spawn(move || {
                if let Err(error) = serve(stream, association, &service, peer.ip())
                    && !matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    )
                {
                    eprintln!("{peer}: {error}");
                }
            })
        {
            eprintln!("cannot start connection handler for {peer}: {error}");
        }
    }
}

fn serve(
    mut stream: TcpStream,
    association: u32,
    service: &Service,
    peer_ip: IpAddr,
) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let mut session = Session::new(stream.local_addr()?.port(), association, peer_ip);
    while let Some(header) = Header::read(&mut stream)? {
        let mut body = vec![0; header.body_length];
        stream.read_exact(&mut body)?;
        let response = session.handle(&header, &body, service)?;
        stream.write_all(&response)?;
    }
    Ok(())
}
