//! Linux and BSD hosts: commands, SCP and shells, given by `JATO_UBUNTU_*`, `JATO_ALPINE_*`,
//! `JATO_FREEBSD_*` and `JATO_OPENBSD_*` (see `support::target`).
use std::time::Duration;

use jato::{Device, DeviceOptions, DeviceProfile, Error, Exit, Mode, Prompt, Secret, ShellOptions};

use crate::support::target::Target;

const PREFIXES: [&str; 4] = ["UBUNTU", "ALPINE", "FREEBSD", "OPENBSD"];
const TIMEOUT: Duration = Duration::from_secs(30);
/// Any common shell prompt, for the first prompt after logging in.
const ANY_PROMPT: &str = r".*[$#%>] ?";
/// The prompt the test sets, so commands are matched exactly.
const TEST_PROMPT: &str = "jato-test> ";

#[tokio::test]
#[ignore]
async fn commands_run() {
    for prefix in PREFIXES {
        let Some(target) = Target::from_env(prefix) else {
            continue;
        };
        let session = target.connect().await;
        let output = session
            .run("uname -s; echo err >&2; exit 4", b"", TIMEOUT)
            .await
            .unwrap();
        let system = String::from_utf8_lossy(&output.stdout);
        assert!(
            ["Linux\n", "FreeBSD\n", "OpenBSD\n"].contains(&system.as_ref()),
            "{prefix}: {system}"
        );
        assert_eq!(output.stderr, b"err\n", "{prefix}");
        assert_eq!(output.exit, Exit::Code(4), "{prefix}");
        let echoed = session.run("cat", b"through stdin", TIMEOUT).await.unwrap();
        assert_eq!(echoed.stdout, b"through stdin", "{prefix}");
    }
}

#[tokio::test]
#[ignore]
async fn files_copy_with_their_mode() {
    for prefix in PREFIXES {
        let Some(target) = Target::from_env(prefix) else {
            continue;
        };
        let session = target.connect().await;
        let data: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
        session
            .scp_upload("jato-test-file", &data, 0o600, TIMEOUT)
            .await
            .unwrap_or_else(|error| panic!("{prefix}: {error}"));
        let check = session
            .run("find jato-test-file -perm 0600", b"", TIMEOUT)
            .await
            .unwrap();
        assert_eq!(check.stdout, b"jato-test-file\n", "{prefix}: mode");
        let copied = session
            .scp_download("jato-test-file", TIMEOUT)
            .await
            .unwrap_or_else(|error| panic!("{prefix}: {error}"));
        assert_eq!(copied, data, "{prefix}");
        session
            .run("rm -f jato-test-file", b"", TIMEOUT)
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore]
async fn shells_run_commands() {
    for prefix in PREFIXES {
        let Some(target) = Target::from_env(prefix) else {
            continue;
        };
        let session = target.connect().await;
        let mut shell = session.shell(&ShellOptions::default()).await.unwrap();
        shell
            .read_until(&Prompt::new(ANY_PROMPT).unwrap(), TIMEOUT)
            .await
            .unwrap_or_else(|error| panic!("{prefix}: {error}"));
        let prompt = Prompt::new(TEST_PROMPT).unwrap();
        shell
            .command(&format!("PS1='{TEST_PROMPT}'"), &prompt, TIMEOUT)
            .await
            .unwrap_or_else(|error| panic!("{prefix}: {error}"));
        let output = shell
            .command("echo jato; echo done", &prompt, TIMEOUT)
            .await
            .unwrap();
        assert_eq!(output, "jato\ndone", "{prefix}");
    }
}

#[tokio::test]
#[ignore]
async fn posix_shell_devices_run_commands() {
    for prefix in PREFIXES {
        let Some(target) = Target::from_env(prefix) else {
            continue;
        };
        let session = target.connect().await;
        let mut profile = DeviceProfile::posix_shell().unwrap();
        profile.enable_command = Some(target.enable.clone());
        let mut device = Device::open(&session, profile, DeviceOptions::default())
            .await
            .unwrap_or_else(|error| panic!("{prefix}: {error}"));
        assert_eq!(device.mode(), Mode::User, "{prefix}");
        assert_eq!(
            device.send_command("echo 'a $ b'; echo end").await.unwrap(),
            "a $ b\nend",
            "{prefix}"
        );
        device.send_command("cd /tmp").await.unwrap();
        assert_eq!(
            device.send_command("pwd").await.unwrap(),
            "/tmp",
            "{prefix}"
        );
        let error = device
            .send_command("ls /jato-no-such-path")
            .await
            .err()
            .unwrap();
        let Error::DeviceCommand { message, .. } = &error else {
            panic!("{prefix}: unexpected error: {error}");
        };
        assert!(message.starts_with("exit status "), "{prefix}: {message}");
        assert!(message.contains("jato-no-such-path"), "{prefix}: {message}");
        let refused = device.send_config(&["true"]).await.err().unwrap();
        assert!(
            refused.to_string().contains("no configuration mode"),
            "{prefix}: {refused}"
        );
        device
            .enable(&Secret::new(String::new()))
            .await
            .unwrap_or_else(|error| panic!("{prefix}: {error}"));
        assert_eq!(device.mode(), Mode::Privileged, "{prefix}");
        assert_eq!(device.send_command("id -u").await.unwrap(), "0", "{prefix}");
        device
            .disable()
            .await
            .unwrap_or_else(|error| panic!("{prefix}: {error}"));
        assert_eq!(device.mode(), Mode::User, "{prefix}");
        assert_ne!(device.send_command("id -u").await.unwrap(), "0", "{prefix}");
    }
}

#[tokio::test]
#[ignore]
async fn files_copy_with_sftp() {
    for prefix in PREFIXES {
        let Some(target) = Target::from_env(prefix) else {
            continue;
        };
        let session = target.connect().await;
        let mut sftp = session
            .sftp(TIMEOUT)
            .await
            .unwrap_or_else(|error| panic!("{prefix}: {error}"));
        let data: Vec<u8> = (0..300 * 1024).map(|i| (i % 251) as u8).collect();
        sftp.create_dir_all("jato-sftp-test/inner", 0o700)
            .await
            .unwrap_or_else(|error| panic!("{prefix}: {error}"));
        sftp.upload("jato-sftp-test/inner/file", &data, 0o600)
            .await
            .unwrap_or_else(|error| panic!("{prefix}: {error}"));
        sftp.upload("jato-sftp-test/inner/file", &data, 0o600)
            .await
            .unwrap_or_else(|error| panic!("{prefix}: replacing: {error}"));
        assert_eq!(
            sftp.download("jato-sftp-test/inner/file").await.unwrap(),
            data,
            "{prefix}"
        );
        let check = session
            .run(
                "find jato-sftp-test -perm 0700 -type d; find jato-sftp-test -perm 0600 -type f; \
                 ls -a jato-sftp-test/inner",
                b"",
                TIMEOUT,
            )
            .await
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&check.stdout),
            "jato-sftp-test\njato-sftp-test/inner\njato-sftp-test/inner/file\n.\n..\nfile\n",
            "{prefix}"
        );
        session
            .run("rm -rf jato-sftp-test", b"", TIMEOUT)
            .await
            .unwrap();
    }
}
