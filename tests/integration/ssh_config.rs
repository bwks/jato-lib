//! OpenSSH client configuration: resolved settings checked against OpenSSH's own `ssh -G`, and
//! connections made from configuration, including the layout Sherpa writes.
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use jato::{ConnectOptions, HostConfig, SshConfig, StrictHostKeyChecking};

use crate::support::prompter::{Asked, ScriptedPrompter};
use crate::support::sshd::{Network, PASSPHRASE, Sshd};

const TIMEOUT: Duration = Duration::from_secs(30);

fn temp_dir(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("jato-it-ssh-config-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// What `ssh -G -F config host` says, by keyword; repeated keywords are joined with spaces.
fn openssh(config: &Path, host: &str) -> HashMap<String, String> {
    let output = Command::new("ssh")
        .arg("-G")
        .arg("-F")
        .arg(config)
        .arg(host)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut settings: HashMap<String, String> = HashMap::new();
    for line in String::from_utf8(output.stdout).unwrap().lines() {
        let (keyword, value) = line.split_once(' ').unwrap_or((line, ""));
        settings
            .entry(keyword.to_string())
            .and_modify(|existing| {
                existing.push(' ');
                existing.push_str(value);
            })
            .or_insert_with(|| value.to_string());
    }
    settings
}

/// A `ProxyJump` value as `ssh -G` prints it, with the brackets it puts around a single
/// jump host's name or IPv4 address removed, so it compares with a list's form.
fn normalize_jumps(value: &str) -> String {
    let parts: Vec<String> = value
        .split(',')
        .map(|part| match (part.find('['), part.find(']')) {
            (Some(open), Some(close)) if !part[open + 1..close].contains(':') => {
                format!(
                    "{}{}{}",
                    &part[..open],
                    &part[open + 1..close],
                    &part[close + 1..]
                )
            }
            _ => part.to_string(),
        })
        .collect();
    parts.join(",")
}

/// A list of files as `ssh -G` prints it: space-separated, or `none` for an empty list.
fn files_as_openssh_shows_them(files: &[PathBuf]) -> String {
    if files.is_empty() {
        return "none".into();
    }
    let shown: Vec<String> = files
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    shown.join(" ")
}

/// Jato's settings in `ssh -G`'s words.
fn jato_view(host: &HostConfig) -> HashMap<&'static str, String> {
    let jumps: Vec<String> = host
        .proxy_jump
        .iter()
        .map(|jump| {
            let mut text = String::new();
            if let Some(user) = &jump.user {
                text.push_str(user);
                text.push('@');
            }
            if jump.host.contains(':') {
                text.push_str(&format!("[{}]", jump.host));
            } else {
                text.push_str(&jump.host);
            }
            if let Some(port) = jump.port {
                text.push_str(&format!(":{port}"));
            }
            text
        })
        .collect();
    let strict = match host.strict_host_key_checking {
        StrictHostKeyChecking::Yes => "true",
        StrictHostKeyChecking::No => "false",
        StrictHostKeyChecking::AcceptNew => "accept-new",
        StrictHostKeyChecking::Ask => "ask",
        _ => "unknown",
    };
    let known_hosts = files_as_openssh_shows_them(&host.known_hosts);
    let global_known_hosts = files_as_openssh_shows_them(&host.global_known_hosts);
    let mut view = HashMap::from([
        ("hostname", host.hostname.clone()),
        ("user", host.user.clone()),
        ("port", host.port.to_string()),
        (
            "identitiesonly",
            if host.identities_only { "yes" } else { "no" }.into(),
        ),
        ("stricthostkeychecking", strict.into()),
        ("userknownhostsfile", known_hosts),
        ("globalknownhostsfile", global_known_hosts),
        (
            "connecttimeout",
            host.connect_timeout
                .map_or("none".into(), |timeout| timeout.as_secs().to_string()),
        ),
    ]);
    if !jumps.is_empty() {
        view.insert("proxyjump", jumps.join(","));
    }
    if let Some(interval) = host.server_alive_interval {
        view.insert("serveraliveinterval", interval.as_secs().to_string());
    }
    if let Some(max) = host.server_alive_count_max {
        view.insert("serveralivecountmax", max.to_string());
    }
    view
}

/// Check that Jato resolves each of `hosts` as OpenSSH does, from the file `config`.
fn assert_matches_openssh(config: &Path, hosts: &[&str]) {
    let jato = SshConfig::load_file(config).unwrap();
    for host in hosts {
        let ours = jato.host(host).unwrap();
        let theirs = openssh(config, host);
        for (keyword, value) in jato_view(&ours)
            .into_iter()
            .filter(|(keyword, _)| *keyword != "proxyjump")
        {
            assert_eq!(
                theirs.get(keyword).map(String::as_str),
                Some(value.as_str()),
                "{host}: {keyword}"
            );
        }
        let their_jumps = theirs.get("proxyjump").map(|jumps| normalize_jumps(jumps));
        assert_eq!(
            their_jumps.as_ref(),
            jato_view(&ours).get("proxyjump"),
            "{host}: proxyjump"
        );
        let absolute: Vec<String> = ours
            .identity_files
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        if !absolute.is_empty() && absolute.iter().all(|path| path.starts_with('/')) {
            assert_eq!(
                theirs.get("identityfile"),
                Some(&absolute.join(" ")),
                "{host}"
            );
        }
    }
}

/// Sherpa's lab block, as its template writes it.
fn sherpa_lab_block(
    aliases: &str,
    hostname: &str,
    port: u16,
    user: &str,
    jump: &str,
    key: &Path,
) -> String {
    format!(
        "
Host {aliases}
    HostName {hostname}
    Port {port}
    User {user}
    ProxyJump {jump}
    IdentityFile {key}
    IdentitiesOnly yes
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    PubkeyAcceptedAlgorithms +ssh-rsa
    HostkeyAlgorithms +ssh-rsa
    KexAlgorithms +diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1
",
        key = key.display()
    )
}

#[test]
#[ignore]
fn settings_match_openssh() {
    let dir = temp_dir("openssh");
    let lab = dir.join("lab");
    fs::create_dir_all(&lab).unwrap();
    fs::write(
        lab.join("sherpa_ssh_config"),
        sherpa_lab_block(
            "192.0.2.21 ios01.abcd1234 ios01.abcd1234.sherpa.lab.local",
            "192.0.2.21",
            22,
            "sherpa",
            "owner@192.0.2.1",
            &lab.join("sherpa_ssh_key"),
        ),
    )
    .unwrap();
    fs::write(
        dir.join("sherpa_lab_hosts"),
        format!(
            "# Sherpa lab SSH configs - managed by sherpa CLI\nInclude {}\n",
            lab.join("sherpa_ssh_config").display()
        ),
    )
    .unwrap();
    fs::write(
        dir.join("config"),
        format!(
            "Include {}

Host r1 *.lab !core.lab
    HostName %h.example.net
    User admin
    Port 830
    ProxyJump owner@192.0.2.1,admin@[2001:db8::1]:2222
    StrictHostKeyChecking accept-new
    UserKnownHostsFile ~/kh1 /tmp/kh2
    ConnectTimeout 7
    ServerAliveInterval 15
    ServerAliveCountMax 4
    IdentityFile /keys/one

Host lab-node
    StrictHostKeyChecking accept-new
    UserKnownHostsFile /labs/lab1/known_hosts ~/.ssh/known_hosts
    GlobalKnownHostsFile none

Host *
    User fallback
    IdentityFile /keys/two
    StrictHostKeyChecking yes
",
            dir.join("sherpa_lab_hosts").display()
        ),
    )
    .unwrap();
    assert_matches_openssh(
        &dir.join("config"),
        &[
            "ios01.abcd1234",
            "ios01.abcd1234.sherpa.lab.local",
            "192.0.2.21",
            "r1",
            "edge.lab",
            "core.lab",
            "lab-node",
            "anything-else",
        ],
    );
}

#[tokio::test]
#[ignore]
async fn a_sherpa_style_config_connects_through_its_server() {
    let network = Network::create();
    let server = Sshd::start_in(&network);
    let node = Sshd::start_in(&network);
    let dir = temp_dir("sherpa");
    let lab = dir.join("lab");
    fs::create_dir_all(&lab).unwrap();
    fs::write(
        lab.join("sherpa_ssh_config"),
        sherpa_lab_block(
            "node1.lab1 node1.lab1.sherpa.lab.local",
            &node.name,
            22,
            "jato",
            &format!("jato@127.0.0.1:{}", server.port),
            &node.dir.join("id_plain"),
        ),
    )
    .unwrap();
    fs::write(
        dir.join("sherpa_lab_hosts"),
        format!("Include {}\n", lab.join("sherpa_ssh_config").display()),
    )
    .unwrap();
    fs::write(
        dir.join("config"),
        format!(
            "Include {index}

Host 127.0.0.1
    IdentityFile {key}
    IdentitiesOnly yes
    StrictHostKeyChecking yes
    UserKnownHostsFile {known_hosts}
",
            index = dir.join("sherpa_lab_hosts").display(),
            key = server.dir.join("id_plain").display(),
            known_hosts = server.known_hosts().display(),
        ),
    )
    .unwrap();
    let config = SshConfig::load_file(dir.join("config")).unwrap();
    for alias in ["node1.lab1", "node1.lab1.sherpa.lab.local"] {
        let route = config.route(alias).unwrap();
        assert_eq!(route.jumps.len(), 1);
        assert!(route.target.legacy_algorithms);
        let session = route.connect(&ConnectOptions::default()).await.unwrap();
        let output = session
            .run("echo through the server", b"", TIMEOUT)
            .await
            .unwrap();
        assert_eq!(output.stdout, b"through the server\n");
        session.close().await.unwrap();
    }
}

#[tokio::test]
#[ignore]
async fn an_encrypted_jump_host_key_asks_for_its_passphrase() {
    let network = Network::create();
    let server = Sshd::start_in(&network);
    let node = Sshd::start_in(&network);
    let dir = temp_dir("sherpa-passphrase");
    fs::write(
        dir.join("config"),
        format!(
            "{lab}
Host 127.0.0.1
    IdentityFile {key}
    IdentitiesOnly yes
    StrictHostKeyChecking yes
    UserKnownHostsFile {known_hosts}
",
            lab = sherpa_lab_block(
                "node1.lab1",
                &node.name,
                22,
                "jato",
                &format!("jato@127.0.0.1:{}", server.port),
                &node.dir.join("id_plain"),
            ),
            key = server.dir.join("id_encrypted").display(),
            known_hosts = server.known_hosts().display(),
        ),
    )
    .unwrap();
    let route = SshConfig::load_file(dir.join("config"))
        .unwrap()
        .route("node1.lab1")
        .unwrap();
    let options = ConnectOptions::default();
    assert!(route.connect(&options).await.is_err());
    let prompter = ScriptedPrompter::new(&[Some(PASSPHRASE)]);
    let session = route
        .connect_with_prompter(&options, prompter.clone())
        .await
        .unwrap();
    assert_eq!(
        prompter.asked(),
        vec![Asked::Passphrase(server.dir.join("id_encrypted"))]
    );
    session.close().await.unwrap();
}

#[tokio::test]
#[ignore]
async fn a_jump_chain_defined_by_aliases_connects() {
    let network = Network::create();
    let jump = Sshd::start_in(&network);
    let target = Sshd::start_in(&network);
    let dir = temp_dir("chain");
    fs::write(
        dir.join("config"),
        format!(
            "Host jumpbox
    HostName 127.0.0.1
    Port {jump_port}
    User jato
    IdentityFile {jump_key}
    IdentitiesOnly yes
    StrictHostKeyChecking yes
    UserKnownHostsFile {jump_known_hosts}

Host inner
    HostName {target_name}
    User jato
    ProxyJump jumpbox
    IdentityFile {target_key}
    IdentitiesOnly yes
    StrictHostKeyChecking yes
    UserKnownHostsFile {target_known_hosts}
",
            jump_port = jump.port,
            jump_key = jump.dir.join("id_plain").display(),
            jump_known_hosts = jump.known_hosts().display(),
            target_name = target.name,
            target_key = target.dir.join("id_plain").display(),
            target_known_hosts = target.known_hosts_by_name().display(),
        ),
    )
    .unwrap();
    let route = SshConfig::load_file(dir.join("config"))
        .unwrap()
        .route("inner")
        .unwrap();
    let session = route.connect(&ConnectOptions::default()).await.unwrap();
    let output = session.run("echo inner", b"", TIMEOUT).await.unwrap();
    assert_eq!(output.stdout, b"inner\n");
}

#[tokio::test]
#[ignore]
async fn a_lab_known_hosts_file_records_then_checks_its_nodes() {
    let network = Network::create();
    let server = Sshd::start_in(&network);
    let node = Sshd::start_in(&network);
    let impostor = Sshd::start_in(&network);
    let dir = temp_dir("lab-known-hosts");
    let lab_known_hosts = dir.join("lab_known_hosts");
    let user_known_hosts = server.known_hosts();
    let write_config = |hostname: &str, checking: &str| {
        fs::write(
            dir.join("config"),
            format!(
                "Host node1.lab1
    HostName {hostname}
    User jato
    ProxyJump jato@127.0.0.1:{server_port}
    IdentityFile {node_key}
    IdentitiesOnly yes
    StrictHostKeyChecking {checking}
    UserKnownHostsFile {lab_known_hosts} {user_known_hosts}
    GlobalKnownHostsFile none

Host 127.0.0.1
    IdentityFile {server_key}
    IdentitiesOnly yes
    StrictHostKeyChecking yes
    UserKnownHostsFile {lab_known_hosts} {user_known_hosts}
    GlobalKnownHostsFile none
",
                server_port = server.port,
                node_key = node.dir.join("id_plain").display(),
                server_key = server.dir.join("id_plain").display(),
                lab_known_hosts = lab_known_hosts.display(),
                user_known_hosts = user_known_hosts.display(),
            ),
        )
        .unwrap();
    };
    let connect = || async {
        SshConfig::load_file(dir.join("config"))
            .unwrap()
            .route("node1.lab1")
            .unwrap()
            .connect(&ConnectOptions::default())
            .await
    };

    // The first connection records the node in the lab's file, not the user's; the server's
    // key is found in the user's file, the second one checked.
    write_config(&node.name, "accept-new");
    connect().await.unwrap();
    let recorded = fs::read_to_string(&lab_known_hosts).unwrap();
    assert!(
        recorded.starts_with(&format!("{} ssh-ed25519 ", node.name)),
        "{recorded}"
    );
    assert!(
        !fs::read_to_string(&user_known_hosts)
            .unwrap()
            .contains(&node.name)
    );

    // Now checked strictly against the lab's file.
    write_config(&node.name, "yes");
    let session = connect().await.unwrap();
    let output = session.run("echo checked", b"", TIMEOUT).await.unwrap();
    assert_eq!(output.stdout, b"checked\n");

    // Another machine answering for the node, as when an address is reused, is refused.
    write_config(&impostor.name, "yes");
    fs::write(
        &lab_known_hosts,
        recorded.replace(&node.name, &impostor.name),
    )
    .unwrap();
    let error = connect().await.err().unwrap();
    assert!(
        matches!(error, jato::Error::HostKeyChanged { .. }),
        "{error}"
    );
}
