mod config;
mod crypto;
mod kms;
mod products;
mod rpc;
mod server;
mod whitelist;
mod wire;

use std::{env, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vlmcsd-rs: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1);
    let mut path = PathBuf::from("vlmcsd.toml");
    if let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--help" | "-h") => {
                println!(
                    "Usage: vlmcsd-rs [--config <path>]\n\nDefault configuration: ./vlmcsd.toml\nSupports KMS V4, V5 and V6 over TCP."
                );
                return Ok(());
            }
            Some("--version" | "-V") => {
                println!("vlmcsd-rs {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            Some("--config") => path = args.next().ok_or("--config requires a file path")?.into(),
            _ => return Err(format!("unknown argument: {}", argument.to_string_lossy()).into()),
        }
    }
    if let Some(argument) = args.next() {
        return Err(format!("unexpected argument: {}", argument.to_string_lossy()).into());
    }
    server::run(config::Config::load(&path)?)
}
