//! Network device CLIs: Cisco IOS and IOS XE, Cisco NX-OS, Arista EOS and Juniper Junos, given
//! by `JATO_IOS_*`, `JATO_NXOS_*`, `JATO_EOS_*` and `JATO_JUNOS_*` (see `support::target`).
//!
//! The tests change each device's configuration and undo it.
use jato::{Auth, Device, DeviceOptions, DeviceProfile, Error, Mode, Secret, Session};

use crate::support::target::Target;

/// The throwaway low-privilege user the IOS enable test creates and removes.
const LOW_USER: &str = "jato-low";
/// Its password, a test fixture.
const LOW_PASSWORD: &str = "jato-low-fixture";
/// The enable secret the IOS test sets and removes, a test fixture.
const ENABLE_SECRET: &str = "jato-enable-fixture";

/// What to expect of one device family.
struct Family {
    prefix: &'static str,
    profile: fn() -> Result<DeviceProfile, Error>,
    /// A command and text its output contains.
    version: (&'static str, &'static str),
    /// A long command and the last line of its output, proving paging is off.
    long: (&'static str, &'static str),
    /// Configuration to apply, a command to show it, and text that shows it applied.
    apply: (&'static [&'static str], &'static str, &'static str),
    /// Configuration that removes it.
    remove: &'static [&'static str],
    /// Configuration whose second line is invalid, and the start of the device's error.
    invalid: (&'static [&'static str], &'static str),
    /// Configuration that sets an enable secret (`{secret}` stands for it) and removes it,
    /// for families with a user mode to disable to. Without one, `disable` and `enable` must
    /// both do nothing, leaving the device privileged.
    enable_secret: Option<(&'static str, &'static str)>,
}

const IOS: Family = Family {
    prefix: "IOS",
    profile: DeviceProfile::cisco_ios,
    version: ("show version", "Cisco IOS"),
    long: ("show running-config", "end"),
    apply: (
        &["interface Loopback100", "description jato-test"],
        "show running-config interface Loopback100",
        "description jato-test",
    ),
    remove: &["no interface Loopback100", "no interface Loopback101"],
    invalid: (
        &[
            "interface Loopback101",
            "not a command",
            "description unreached",
        ],
        "% Invalid input",
    ),
    enable_secret: Some(("enable secret {secret}", "no enable secret")),
};

const EOS: Family = Family {
    prefix: "EOS",
    profile: DeviceProfile::arista_eos,
    version: ("show version", "Arista"),
    long: ("show running-config", "end"),
    apply: (
        &["interface Loopback100", "description jato-test"],
        "show running-config interfaces Loopback100",
        "description jato-test",
    ),
    remove: &["no interface Loopback100", "no interface Loopback101"],
    invalid: (
        &[
            "interface Loopback101",
            "not a command",
            "description unreached",
        ],
        "% Invalid input",
    ),
    enable_secret: Some(("enable password {secret}", "no enable password")),
};

const NXOS: Family = Family {
    prefix: "NXOS",
    profile: DeviceProfile::cisco_nxos,
    version: ("show version", "NX-OS"),
    long: ("show running-config | include hostname", ""),
    apply: (
        &["interface loopback100", "description jato-test"],
        "show running-config interface loopback100",
        "description jato-test",
    ),
    remove: &["no interface loopback100", "no interface loopback101"],
    invalid: (
        &[
            "interface loopback101",
            "not a command",
            "description unreached",
        ],
        "% Invalid command",
    ),
    enable_secret: None,
};

const JUNOS: Family = Family {
    prefix: "JUNOS",
    profile: DeviceProfile::juniper_junos,
    version: ("show version", "Junos"),
    long: ("show configuration | display set | count", ""),
    apply: (
        &["set interfaces lo0 description jato-test"],
        "show configuration interfaces lo0",
        "description jato-test;",
    ),
    remove: &["delete interfaces lo0 description"],
    invalid: (
        &[
            "set interfaces lo0 description jato-uncommitted",
            "set not-a-statement",
        ],
        "syntax error",
    ),
    enable_secret: None,
};

async fn open(target: &Target, family: &Family, session: &Session) -> Device {
    let profile = (family.profile)().unwrap();
    Device::open(session, profile, DeviceOptions::default())
        .await
        .unwrap_or_else(|error| panic!("{}: {error}", target.prefix))
}

async fn commands_and_paging(family: &Family) {
    let Some(target) = Target::from_env(family.prefix) else {
        return;
    };
    let session = target.connect().await;
    let mut device = open(&target, family, &session).await;
    assert_eq!(device.mode(), Mode::Privileged, "{}", family.prefix);
    let (command, marker) = family.version;
    let version = device.send_command(command).await.unwrap();
    assert!(version.contains(marker), "{}: {version}", family.prefix);
    let (command, last) = family.long;
    let output = device.send_command(command).await.unwrap();
    if !last.is_empty() {
        assert_eq!(
            output.lines().last(),
            Some(last),
            "{}: {output}",
            family.prefix
        );
    }
    let error = device
        .send_command("show nonsense-jato")
        .await
        .err()
        .unwrap();
    assert!(
        matches!(error, Error::DeviceCommand { .. }),
        "{}: {error}",
        family.prefix
    );
    assert_eq!(device.mode(), Mode::Privileged, "{}", family.prefix);
}

async fn configuration(family: &Family) {
    let Some(target) = Target::from_env(family.prefix) else {
        return;
    };
    let session = target.connect().await;
    let mut device = open(&target, family, &session).await;
    let (lines, show, applied) = family.apply;
    device
        .send_config(lines)
        .await
        .unwrap_or_else(|error| panic!("{}: {error}", family.prefix));
    assert_eq!(device.mode(), Mode::Privileged, "{}", family.prefix);
    let shown = device.send_command(show).await.unwrap();
    assert!(shown.contains(applied), "{}: {shown}", family.prefix);

    let (lines, message_start) = family.invalid;
    let error = device.send_config(lines).await.err().unwrap();
    let Error::DeviceCommand { step, message, .. } = &error else {
        panic!("{}: unexpected error: {error}", family.prefix);
    };
    assert_eq!(step, "config line 2", "{}", family.prefix);
    assert!(
        message.starts_with(message_start),
        "{}: {message}",
        family.prefix
    );
    assert_eq!(device.mode(), Mode::Privileged, "{}", family.prefix);
    let shown = device.send_command(show).await.unwrap();
    assert!(
        !shown.contains("jato-uncommitted"),
        "{}: {shown}",
        family.prefix
    );

    device
        .send_config(family.remove)
        .await
        .unwrap_or_else(|error| panic!("{}: {error}", family.prefix));
}

async fn disable_and_enable(family: &Family) {
    let Some(target) = Target::from_env(family.prefix) else {
        return;
    };
    let session = target.connect().await;
    let mut device = open(&target, family, &session).await;
    assert_eq!(device.mode(), Mode::Privileged, "{}", family.prefix);
    let Some((set, remove)) = family.enable_secret else {
        device
            .disable()
            .await
            .unwrap_or_else(|error| panic!("{}: {error}", family.prefix));
        assert_eq!(device.mode(), Mode::Privileged, "{}", family.prefix);
        device
            .enable(&Secret::new(String::new()))
            .await
            .unwrap_or_else(|error| panic!("{}: {error}", family.prefix));
        assert_eq!(device.mode(), Mode::Privileged, "{}", family.prefix);
        return;
    };
    device
        .send_config(&[&set.replace("{secret}", ENABLE_SECRET)])
        .await
        .unwrap_or_else(|error| panic!("{}: {error}", family.prefix));
    device
        .disable()
        .await
        .unwrap_or_else(|error| panic!("{}: {error}", family.prefix));
    assert_eq!(device.mode(), Mode::User, "{}", family.prefix);
    device.disable().await.unwrap();
    assert_eq!(device.mode(), Mode::User, "{}", family.prefix);
    device
        .enable(&Secret::new(ENABLE_SECRET.into()))
        .await
        .unwrap_or_else(|error| panic!("{}: {error}", family.prefix));
    assert_eq!(device.mode(), Mode::Privileged, "{}", family.prefix);
    device
        .send_config(&[remove])
        .await
        .unwrap_or_else(|error| panic!("{}: {error}", family.prefix));
}

#[tokio::test]
#[ignore]
async fn eos_disable_and_enable() {
    disable_and_enable(&EOS).await;
}

#[tokio::test]
#[ignore]
async fn nxos_disable_and_enable() {
    disable_and_enable(&NXOS).await;
}

#[tokio::test]
#[ignore]
async fn junos_disable_and_enable() {
    disable_and_enable(&JUNOS).await;
}

#[tokio::test]
#[ignore]
async fn ios_commands_and_paging() {
    commands_and_paging(&IOS).await;
}

#[tokio::test]
#[ignore]
async fn ios_configuration() {
    configuration(&IOS).await;
}

#[tokio::test]
#[ignore]
async fn eos_commands_and_paging() {
    commands_and_paging(&EOS).await;
}

#[tokio::test]
#[ignore]
async fn eos_configuration() {
    configuration(&EOS).await;
}

#[tokio::test]
#[ignore]
async fn nxos_commands_and_paging() {
    commands_and_paging(&NXOS).await;
}

#[tokio::test]
#[ignore]
async fn nxos_configuration() {
    configuration(&NXOS).await;
}

#[tokio::test]
#[ignore]
async fn junos_commands_and_paging() {
    commands_and_paging(&JUNOS).await;
}

#[tokio::test]
#[ignore]
async fn junos_configuration() {
    configuration(&JUNOS).await;
}

#[tokio::test]
#[ignore]
/// One test for both, as each sets and removes the same device's enable secret.
async fn ios_disable_and_enable_from_a_low_privilege_login() {
    disable_and_enable(&IOS).await;
    let Some(target) = Target::from_env(IOS.prefix) else {
        return;
    };
    let admin_session = target.connect().await;
    let mut admin = open(&target, &IOS, &admin_session).await;
    admin
        .send_config(&[
            &format!("username {LOW_USER} privilege 1 secret {LOW_PASSWORD}"),
            &format!("enable secret {ENABLE_SECRET}"),
        ])
        .await
        .unwrap();

    let low = Auth::new(LOW_USER).password(Secret::new(LOW_PASSWORD.into()));
    let low_session = target.connect_with(low).await;
    let mut device = open(&target, &IOS, &low_session).await;
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
