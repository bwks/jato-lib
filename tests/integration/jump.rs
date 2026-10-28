//! Connecting through jump hosts, as OpenSSH's `ProxyJump` does.
//!
//! Each target is on a private Docker network and is reached by its container name, which
//! resolves only inside that network, so a login proves the connection went through the
//! jump hosts.
use crate::support::prompter::ScriptedPrompter;
use crate::support::sshd::{Network, PASSWORD, Sshd, USER};
use jato::{Auth, ConnectOptions, Error, Hop, HostKeyPolicy, Node, Secret, Session};
use std::thread;
use tokio::runtime;

/// The stack a connection through two jump hosts may use on the thread that polls it,
/// runtime included. A Linux debug build needs about 160 KiB; before the connection futures
/// were boxed it needed more than 384 KiB, and a Windows debug build overflowed the 1 MiB
/// main thread.
const MAIN_THREAD_STACK_BUDGET: usize = 256 * 1024;

fn password() -> Auth {
    Auth::new(USER).password(Secret::new(PASSWORD.into()))
}

/// The first jump host, reached directly on its published port.
fn entry_hop(sshd: &Sshd) -> Hop {
    Hop::new(
        Node::new("127.0.0.1", sshd.port),
        password(),
        HostKeyPolicy::strict(sshd.known_hosts()),
    )
}

/// A server behind a jump host, reached by its name on the Docker network.
fn inner_hop(sshd: &Sshd) -> Hop {
    Hop::new(
        Node::new(sshd.name.clone(), 22),
        password(),
        HostKeyPolicy::strict(sshd.known_hosts_by_name()),
    )
}

#[tokio::test]
#[ignore]
async fn through_one_jump_host() {
    let network = Network::create();
    let jump = Sshd::start_in(&network);
    let target = Sshd::start_in(&network);
    let session = Session::connect_via(
        &[entry_hop(&jump)],
        &inner_hop(&target),
        &ConnectOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(session.node(), &Node::new(target.name.clone(), 22));
    session.close().await.unwrap();
}

#[tokio::test]
#[ignore]
async fn through_two_jump_hosts() {
    let network = Network::create();
    let first = Sshd::start_in(&network);
    let second = Sshd::start_in(&network);
    let target = Sshd::start_in(&network);
    let session = Session::connect_via(
        &[entry_hop(&first), inner_hop(&second)],
        &inner_hop(&target),
        &ConnectOptions::default(),
    )
    .await
    .unwrap();
    session.close().await.unwrap();
}

#[tokio::test]
#[ignore]
async fn each_hop_checks_its_own_host_key() {
    let network = Network::create();
    let jump = Sshd::start_in(&network);
    let target = Sshd::start_in(&network);
    let unknown = Hop::new(
        Node::new(target.name.clone(), 22),
        password(),
        HostKeyPolicy::strict(target.dir.join("empty_known_hosts")),
    );
    let error = Session::connect_via(&[entry_hop(&jump)], &unknown, &ConnectOptions::default())
        .await
        .err()
        .unwrap();
    let Error::HostKeyUnknown { node, .. } = &error else {
        panic!("unexpected error: {error}");
    };
    assert_eq!(node, &Node::new(target.name.clone(), 22));
}

#[tokio::test]
#[ignore]
async fn each_hop_logs_in_with_its_own_credentials() {
    let network = Network::create();
    let jump = Sshd::start_in(&network);
    let target = Sshd::start_in(&network);
    let wrong = Hop::new(
        Node::new(target.name.clone(), 22),
        Auth::new(USER).password(Secret::new("wrong-password".into())),
        HostKeyPolicy::strict(target.known_hosts_by_name()),
    );
    let error = Session::connect_via(&[entry_hop(&jump)], &wrong, &ConnectOptions::default())
        .await
        .err()
        .unwrap();
    let Error::AuthFailed { node, .. } = &error else {
        panic!("unexpected error: {error}");
    };
    assert_eq!(node, &Node::new(target.name.clone(), 22));
}

#[tokio::test]
#[ignore]
async fn an_unreachable_next_hop_names_both_ends() {
    let network = Network::create();
    let jump = Sshd::start_in(&network);
    let missing = Hop::new(
        Node::new("jato-no-such-host", 22),
        password(),
        HostKeyPolicy::Insecure,
    );
    let error = Session::connect_via(&[entry_hop(&jump)], &missing, &ConnectOptions::default())
        .await
        .err()
        .unwrap();
    let Error::Tunnel { via, node, .. } = &error else {
        panic!("unexpected error: {error}");
    };
    assert_eq!(via, &Node::new("127.0.0.1", jump.port));
    assert_eq!(node, &Node::new("jato-no-such-host", 22));
}

#[tokio::test]
#[ignore]
async fn an_unknown_jump_host_is_asked_about() {
    let network = Network::create();
    let jump = Sshd::start_in(&network);
    let target = Sshd::start_in(&network);
    let file = jump.dir.join("ask_known_hosts");
    let prompter = ScriptedPrompter::new(&[Some("yes")]);
    let entry = Hop::new(
        Node::new("127.0.0.1", jump.port),
        password().prompter(prompter.clone()),
        HostKeyPolicy::ask(&file),
    );
    let session = Session::connect_via(&[entry], &inner_hop(&target), &ConnectOptions::default())
        .await
        .unwrap();
    assert_eq!(session.node(), &Node::new(target.name.clone(), 22));
    assert_eq!(prompter.asked().len(), 2);
}

/// A connection through jump hosts must leave room in a Windows main thread's 1 MiB stack in
/// a debug build, where frames are larger than on Linux, so programs that poll it from their
/// main thread need no bigger thread. The connection is polled from a thread with
/// [`MAIN_THREAD_STACK_BUDGET`] while the runtime's workers run russh's session tasks, as in a
/// program using `#[tokio::main]`.
#[test]
#[ignore]
fn two_jump_hosts_fit_in_a_small_main_thread_stack() {
    let network = Network::create();
    let first = Sshd::start_in(&network);
    let second = Sshd::start_in(&network);
    let target = Sshd::start_in(&network);
    let jumps = [entry_hop(&first), inner_hop(&second)];
    let target_hop = inner_hop(&target);
    let connecting = thread::Builder::new()
        .stack_size(MAIN_THREAD_STACK_BUDGET)
        .spawn(move || {
            let runtime = runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let session = Session::connect_via(&jumps, &target_hop, &ConnectOptions::default())
                    .await
                    .unwrap();
                session.close().await.unwrap();
            });
        })
        .unwrap();
    connecting.join().unwrap();
}
