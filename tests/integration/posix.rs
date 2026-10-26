//! The `posix_shell` device profile against the container's `sh`, including `enable` through
//! `sudo`, which the test image sets up to ask for the user's password.
use std::time::Duration;

use jato::{
    Auth, ConnectOptions, Device, DeviceOptions, DeviceProfile, Error, Hop, HostKeyPolicy, Mode,
    Node, Secret, Session,
};

use crate::support::sshd::{PASSWORD, Sshd, USER};

async fn device(sshd: &Sshd) -> (Session, Device) {
    device_with(sshd, DeviceProfile::posix_shell().unwrap()).await
}

async fn device_with(sshd: &Sshd, profile: DeviceProfile) -> (Session, Device) {
    let hop = Hop::new(
        Node::new("127.0.0.1", sshd.port),
        Auth::new(USER).password(Secret::new(PASSWORD.into())),
        HostKeyPolicy::Strict(sshd.known_hosts()),
    );
    let session = Session::connect(&hop, &ConnectOptions::default())
        .await
        .unwrap();
    let mut options = DeviceOptions::default();
    options.command_timeout = Duration::from_secs(20);
    let device = Device::open(&session, profile, options).await.unwrap();
    (session, device)
}

#[tokio::test]
#[ignore]
async fn enable_with_the_sudo_password() {
    let sshd = Sshd::start();
    let (_session, mut device) = device(&sshd).await;
    assert_eq!(device.mode(), Mode::User);
    assert_ne!(device.send_command("id -u").await.unwrap(), "0");
    device.enable(&Secret::new(PASSWORD.into())).await.unwrap();
    assert_eq!(device.mode(), Mode::Privileged);
    assert_eq!(device.send_command("id -u").await.unwrap(), "0");
    assert_eq!(
        device.send_command("echo still here").await.unwrap(),
        "still here"
    );
}

#[tokio::test]
#[ignore]
async fn disable_leaves_the_root_shell() {
    let sshd = Sshd::start();
    let (_session, mut device) = device(&sshd).await;
    device.disable().await.unwrap();
    assert_eq!(device.mode(), Mode::User);
    device.enable(&Secret::new(PASSWORD.into())).await.unwrap();
    assert_eq!(device.send_command("id -u").await.unwrap(), "0");
    device.disable().await.unwrap();
    assert_eq!(device.mode(), Mode::User);
    assert_ne!(device.send_command("id -u").await.unwrap(), "0");
    device.enable(&Secret::new(PASSWORD.into())).await.unwrap();
    assert_eq!(device.mode(), Mode::Privileged);
}

#[tokio::test]
#[ignore]
async fn a_wrong_sudo_password_is_refused() {
    let sshd = Sshd::start();
    let (_session, mut device) = device(&sshd).await;
    let error = device
        .enable(&Secret::new("wrong-password".into()))
        .await
        .err()
        .unwrap();
    let Error::DeviceCommand { step, message, .. } = &error else {
        panic!("unexpected error: {error}");
    };
    assert_eq!(step, "enable");
    assert_eq!(message, "the password was refused");
    assert!(!error.to_string().contains("wrong-password"));
    assert_eq!(device.mode(), Mode::User);
    assert_ne!(device.send_command("id -u").await.unwrap(), "0");
}

#[tokio::test]
#[ignore]
async fn a_missing_enable_command_is_reported() {
    let sshd = Sshd::start();
    let mut profile = DeviceProfile::posix_shell().unwrap();
    profile.enable_command = Some("doas -s".into());
    let (_session, mut device) = device_with(&sshd, profile).await;
    let error = device
        .enable(&Secret::new(PASSWORD.into()))
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("not found"), "{error}");
    assert_eq!(device.mode(), Mode::User);
}
