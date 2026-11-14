//! Telnet against servers built in each test on a local TCP listener, scripted to act as a
//! QEMU serial console does (its bytes are the ones captured from QEMU). They need no
//! Docker and are not ignored, except `connect_via`, which goes through the test SSH
//! server.
use std::time::Duration;

use jato::{
    Auth, ConnectOptions, Error, Event, Hop, HostKeyPolicy, Node, Secret, Session, Telnet,
    TelnetOptions,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::support::sshd::{PASSWORD, Sshd, USER};

/// What a QEMU serial console sends on connect: `WILL ECHO`, `WILL SGA`, `WILL BINARY`,
/// `DO BINARY`.
const QEMU_GREETING: [u8; 12] = [
    0xFF, 0xFB, 0x01, 0xFF, 0xFB, 0x03, 0xFF, 0xFB, 0x00, 0xFF, 0xFD, 0x00,
];
/// The system `telnet`'s answer: `DO ECHO`, `DO SGA`, `DO BINARY`, `WILL BINARY`.
const QEMU_REPLY: [u8; 12] = [
    0xFF, 0xFD, 0x01, 0xFF, 0xFD, 0x03, 0xFF, 0xFD, 0x00, 0xFF, 0xFB, 0x00,
];
const LOGIN: &[u8] = b"\r\nubu01 login: ";
/// How long a console may stay silent in these tests before it is taken to be in use.
const QUIET: Duration = Duration::from_millis(300);

fn options() -> TelnetOptions {
    let mut options = TelnetOptions::default();
    options.negotiation_timeout = Some(QUIET);
    options
}

async fn listen(host: &str) -> (TcpListener, Node) {
    let listener = TcpListener::bind((host, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, Node::new(host, port))
}

/// A QEMU console: it greets, checks the client's reply, then reads `typed` bytes and sends
/// `output`. It returns what it read after the reply, once the client closes.
fn qemu_console(listener: TcpListener, output: &'static [u8]) -> JoinHandle<Vec<u8>> {
    tokio::spawn(serve_qemu(listener, output))
}

async fn serve_qemu(listener: TcpListener, output: &'static [u8]) -> Vec<u8> {
    let (mut stream, _) = listener.accept().await.unwrap();
    stream
        .write_all(&[&QEMU_GREETING[..], LOGIN].concat())
        .await
        .unwrap();
    let mut reply = [0; 12];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, QEMU_REPLY, "the reply to the QEMU greeting");
    stream.write_all(output).await.unwrap();
    let mut typed = Vec::new();
    stream.read_to_end(&mut typed).await.unwrap();
    typed
}

/// Everything the console sends until it has sent `want` bytes.
async fn output(telnet: &mut Telnet, want: usize) -> Vec<u8> {
    let mut received = Vec::new();
    while received.len() < want {
        match telnet.next_event().await.unwrap() {
            Some(Event::Stdout(bytes)) => received.extend(bytes),
            other => panic!("unexpected {other:?}"),
        }
    }
    received
}

#[tokio::test]
async fn connects_and_negotiates_as_the_system_telnet_does() {
    let (listener, node) = listen("127.0.0.1").await;
    let console = qemu_console(listener, b"x\xFFy");
    let mut telnet = Telnet::connect(&node, &options()).await.unwrap();
    assert_eq!(telnet.node(), &node);
    assert_eq!(
        output(&mut telnet, LOGIN.len() + 3).await,
        [LOGIN, b"x\xFFy"].concat()
    );
    telnet.send_bytes(b"root\r\xFF").await.unwrap();
    drop(telnet);
    assert_eq!(console.await.unwrap(), b"root\r\xFF\xFF");
}

#[tokio::test]
async fn resizing_a_qemu_console_sends_nothing() {
    let (listener, node) = listen("127.0.0.1").await;
    let console = qemu_console(listener, b"");
    let mut telnet = Telnet::connect(&node, &options()).await.unwrap();
    telnet.resize(132, 50).await.unwrap();
    telnet.send_bytes(b"a").await.unwrap();
    drop(telnet);
    assert_eq!(console.await.unwrap(), b"a");
}

#[tokio::test]
async fn send_break_sends_iac_break() {
    let (listener, node) = listen("127.0.0.1").await;
    let console = qemu_console(listener, b"");
    let mut telnet = Telnet::connect(&node, &options()).await.unwrap();
    telnet.send_break().await.unwrap();
    drop(telnet);
    assert_eq!(console.await.unwrap(), [0xFF, 0xF3]);
}

#[tokio::test]
async fn a_closed_port_is_refused() {
    let (listener, node) = listen("127.0.0.1").await;
    drop(listener);
    let error = Telnet::connect(&node, &options()).await.unwrap_err();
    assert!(
        matches!(&error, Error::TelnetRefused { node: refused, via: None, .. } if refused == &node),
        "{error:?}"
    );
}

/// A listener whose accept queue is full drops new connection attempts on Linux, so they
/// hang as an unreachable address does. Other systems refuse them instead.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_connection_that_hangs_times_out() {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = socket.listen(1).unwrap();
    let address = listener.local_addr().unwrap();
    let mut held = Vec::new();
    while let Ok(Ok(stream)) =
        tokio::time::timeout(Duration::from_millis(200), TcpStream::connect(address)).await
    {
        held.push(stream);
        assert!(held.len() < 16, "the accept queue never filled");
    }
    let mut options = options();
    options.connect_timeout = Duration::from_millis(300);
    let node = Node::new("127.0.0.1", address.port());
    let error = Telnet::connect(&node, &options).await.unwrap_err();
    assert!(
        matches!(error, Error::TelnetTimeout { after, via: None, .. } if after == options.connect_timeout),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_silent_console_is_in_use() {
    let (listener, node) = listen("127.0.0.1").await;
    let holder = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
    });
    let error = Telnet::connect(&node, &options()).await.unwrap_err();
    assert!(
        matches!(error, Error::TelnetInUse { after, .. } if after == QUIET),
        "{error:?}"
    );
    holder.await.unwrap();
}

#[tokio::test]
async fn a_console_that_closes_at_once_is_closed() {
    let (listener, node) = listen("127.0.0.1").await;
    let closer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        drop(stream);
    });
    let error = Telnet::connect(&node, &options()).await.unwrap_err();
    assert!(matches!(error, Error::TelnetClosed { .. }), "{error:?}");
    closer.await.unwrap();
}

#[tokio::test]
async fn a_console_closed_by_the_server_ends_and_refuses_input() {
    let (listener, node) = listen("127.0.0.1").await;
    let console = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream
            .write_all(&[&QEMU_GREETING[..], b"bye"].concat())
            .await
            .unwrap();
    });
    let mut telnet = Telnet::connect(&node, &options()).await.unwrap();
    console.await.unwrap();
    assert_eq!(output(&mut telnet, 3).await, b"bye");
    assert_eq!(telnet.next_event().await.unwrap(), None);
    let error = telnet.send_bytes(b"a").await.unwrap_err();
    assert!(matches!(error, Error::TelnetClosed { .. }), "{error:?}");
}

/// The console listens on the address the test SSH server's container reaches this host
/// by, and is reached through the SSH server's `direct-tcpip` channel.
#[tokio::test]
#[ignore]
async fn connect_via_reaches_the_console_through_an_ssh_server() {
    let sshd = Sshd::start();
    let host = sshd.gateway();
    let (listener, node) = listen(&host).await;
    let console = qemu_console(listener, b"x");
    let hop = Hop::new(
        Node::new("127.0.0.1", sshd.port),
        Auth::new(USER).password(Secret::new(PASSWORD.into())),
        HostKeyPolicy::strict(sshd.known_hosts()),
    );
    let session = Session::connect(&hop, &ConnectOptions::default())
        .await
        .unwrap();
    let mut telnet = Telnet::connect_via(&session, &node, &options())
        .await
        .unwrap();
    assert_eq!(
        output(&mut telnet, LOGIN.len() + 1).await,
        [LOGIN, b"x"].concat()
    );
    telnet.send_bytes(b"root\r").await.unwrap();
    telnet.send_break().await.unwrap();
    drop(telnet);
    assert_eq!(console.await.unwrap(), b"root\r\xFF\xF3");

    let (closed, closed_node) = listen(&host).await;
    drop(closed);
    let error = Telnet::connect_via(&session, &closed_node, &options())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::TelnetRefused { via: Some(via), .. } if via == session.node()),
        "{error:?}"
    );
    session.close().await.unwrap();
}
