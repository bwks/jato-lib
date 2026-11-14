//! A serial console in this terminal, as `telnet <host> <port>` gives, directly or through an
//! SSH server from the OpenSSH configuration.
//!
//! Run it with `cargo run --example console --features terminal,telnet -- <host> <port>`,
//! adding `--via <ssh host>` to reach the console through that SSH server, as named in
//! `~/.ssh/config` (or in the file given with `--config <file>`). Leave with `Ctrl+]`, or
//! `~.` at the start of a line.
use std::env;
use std::process::ExitCode;
use std::sync::Arc;

use jato::{ConnectOptions, Error, Node, SshConfig, Telnet, TelnetOptions, TerminalPrompter};

/// The command line.
struct Arguments {
    host: String,
    port: u16,
    via: Option<String>,
    config: Option<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let Some(arguments) = parse(env::args().skip(1).collect()) else {
        eprintln!("usage: console <host> <port> [--via <ssh host>] [--config <file>]");
        return ExitCode::from(2);
    };
    match run(&arguments).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("console: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse(arguments: Vec<String>) -> Option<Arguments> {
    let mut words = arguments.into_iter();
    let host = words.next()?;
    let port = words.next()?.parse().ok()?;
    let mut parsed = Arguments {
        host,
        port,
        via: None,
        config: None,
    };
    while let Some(flag) = words.next() {
        match flag.as_str() {
            "--via" => parsed.via = Some(words.next()?),
            "--config" => parsed.config = Some(words.next()?),
            _ => return None,
        }
    }
    Some(parsed)
}

async fn run(arguments: &Arguments) -> Result<(), Error> {
    let node = Node::new(&arguments.host, arguments.port);
    let options = TelnetOptions::default();
    let Some(via) = &arguments.via else {
        let mut telnet = Telnet::connect(&node, &options).await?;
        telnet.interactive().await?;
        return Ok(());
    };
    let config = match &arguments.config {
        Some(file) => SshConfig::load_file(file)?,
        None => SshConfig::load()?,
    };
    let session = config
        .route(via)?
        .connect_with_prompter(
            &ConnectOptions::default(),
            Arc::new(TerminalPrompter::new()),
        )
        .await?;
    let mut telnet = Telnet::connect_via(&session, &node, &options).await?;
    telnet.interactive().await?;
    drop(telnet);
    session.close().await
}
