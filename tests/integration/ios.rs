//! Cisco IOS devices, such as a Sherpa lab node. Skipped unless `JATO_IOS_HOST` is set.
//!
//! - `JATO_IOS_HOST`, `JATO_IOS_USER` and `JATO_IOS_KEY` (a private key file): a privilege 15
//!   login, checked with the `Insecure` host key policy as for a lab node.
//! - `JATO_JUMP_HOST` and `JATO_JUMP_USER`, optional: a jump host reached with the agent and
//!   the default identities, checked strictly against `~/.ssh/known_hosts`. Not needed for a
//!   Sherpa lab node from the Sherpa server, which reaches the lab network directly.
//!
//! The tests change the device's configuration and undo it: they add `Loopback100` and
//! `Loopback101`, a user `jato-low` and an enable secret.
use std::env;

use jato::{
    Auth, ConnectOptions, Device, DeviceOptions, DeviceProfile, Error, Hop, HostKeyPolicy, Mode,
    Node, Secret, Session,
};

/// The throwaway low-privilege user the enable test creates and removes.
const LOW_USER: &str = "jato-low";
/// Its password, a test fixture.
const LOW_PASSWORD: &str = "jato-low-fixture";
/// The enable secret the test sets and removes, a test fixture.
const ENABLE_SECRET: &str = "jato-enable-fixture";

/// The jump hosts to reach the device through, from the environment.
fn jumps() -> Vec<Hop> {
    let (Ok(host), Ok(user)) = (env::var("JATO_JUMP_HOST"), env::var("JATO_JUMP_USER")) else {
        return Vec::new();
    };
    let known_hosts = env::home_dir().unwrap().join(".ssh").join("known_hosts");
    vec![Hop::new(
        Node::new(host, 22),
        Auth::new(user).agent().default_identities(),
        HostKeyPolicy::Strict(known_hosts),
    )]
}

/// A hop to the device logging in with `auth`.
fn device_hop(auth: Auth) -> Hop {
    let host = env::var("JATO_IOS_HOST").unwrap();
    Hop::new(Node::new(host, 22), auth, HostKeyPolicy::Insecure).allow_legacy_algorithms()
}

/// The privileged login from the environment, or `None` to skip the test.
fn admin_auth() -> Option<Auth> {
    let host = env::var("JATO_IOS_HOST").ok()?;
    let user = env::var("JATO_IOS_USER").unwrap();
    let key = env::var("JATO_IOS_KEY").unwrap();
    eprintln!("testing Cisco IOS at {host}");
    Some(Auth::new(user).key_file(key, None))
}

async fn open(auth: Auth) -> (Session, Device) {
    let session = Session::connect_via(&jumps(), &device_hop(auth), &ConnectOptions::default())
        .await
        .unwrap();
    let device = Device::open(
        &session,
        DeviceProfile::cisco_ios().unwrap(),
        DeviceOptions::default(),
    )
    .await
    .unwrap();
    (session, device)
}

#[tokio::test]
#[ignore]
async fn show_commands_with_paging_off() {
    let Some(auth) = admin_auth() else { return };
    let (_session, mut device) = open(auth).await;
    assert_eq!(device.mode(), Mode::Privileged);
    let version = device.send_command("show version").await.unwrap();
    assert!(version.contains("Cisco IOS Software"), "{version}");
    let config = device.send_command("show running-config").await.unwrap();
    assert_eq!(config.lines().last(), Some("end"), "{config}");
    let declined = device.send_command("clear counters").await.err().unwrap();
    assert!(declined.to_string().contains("confirmation"), "{declined}");
    assert_eq!(device.mode(), Mode::Privileged);
    assert!(device.send_command("show clock").await.is_ok());
    let error = device.send_command("show nonsense").await.err().unwrap();
    let Error::DeviceCommand { step, message, .. } = &error else {
        panic!("unexpected error: {error}");
    };
    assert_eq!(step, "command");
    assert!(message.starts_with("% Invalid input"), "{message}");
}

#[tokio::test]
#[ignore]
async fn configuration_is_applied_and_errors_name_the_line() {
    let Some(auth) = admin_auth() else { return };
    let (_session, mut device) = open(auth).await;
    device
        .send_config(&["interface Loopback100", "description jato-test"])
        .await
        .unwrap();
    assert_eq!(device.mode(), Mode::Privileged);
    let interface = device
        .send_command("show running-config interface Loopback100")
        .await
        .unwrap();
    assert!(interface.contains("description jato-test"), "{interface}");

    let error = device
        .send_config(&[
            "interface Loopback101",
            "not a command",
            "description unreached",
        ])
        .await
        .err()
        .unwrap();
    let Error::DeviceCommand { step, message, .. } = &error else {
        panic!("unexpected error: {error}");
    };
    assert_eq!(step, "config line 2");
    assert!(message.starts_with("% Invalid input"), "{message}");
    assert_eq!(device.mode(), Mode::Privileged);

    device
        .send_config(&["no interface Loopback100", "no interface Loopback101"])
        .await
        .unwrap();
}

#[tokio::test]
#[ignore]
async fn enable_from_a_low_privilege_login() {
    let Some(auth) = admin_auth() else { return };
    let (_admin_session, mut admin) = open(auth).await;
    admin
        .send_config(&[
            &format!("username {LOW_USER} privilege 1 secret {LOW_PASSWORD}"),
            &format!("enable secret {ENABLE_SECRET}"),
        ])
        .await
        .unwrap();

    let low = Auth::new(LOW_USER).password(Secret::new(LOW_PASSWORD.into()));
    let (_low_session, mut device) = open(low).await;
    assert_eq!(device.mode(), Mode::User);
    let refused = device
        .enable(&Secret::new("wrong-secret".into()))
        .await
        .err()
        .unwrap();
    assert!(matches!(refused, Error::DeviceCommand { .. }), "{refused}");
    assert!(!refused.to_string().contains("wrong-secret"));
    assert_eq!(device.mode(), Mode::User);
    device
        .enable(&Secret::new(ENABLE_SECRET.into()))
        .await
        .unwrap();
    assert_eq!(device.mode(), Mode::Privileged);

    admin
        .send_config(&[&format!("no username {LOW_USER}"), "no enable secret"])
        .await
        .unwrap();
}
