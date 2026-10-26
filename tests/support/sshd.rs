//! A disposable OpenSSH server in a container, and the keys to log in to it.
use std::fs;
use std::io::Read;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

pub const IMAGE: &str = "jato-test-sshd";
pub const USER: &str = "jato";
pub const PASSWORD: &str = "jato-test-password";
pub const PASSPHRASE: &str = "jato-test-passphrase";

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

/// A running test server. The container and its files are removed on drop.
pub struct Sshd {
    container: String,
    pub port: u16,
    pub dir: PathBuf,
    /// The server's ed25519 host key, as an OpenSSH public key line.
    pub host_key: String,
    /// The server's RSA host key, as an OpenSSH public key line.
    pub rsa_host_key: String,
}

/// An ssh-agent holding the unencrypted test key. It is stopped on drop.
pub struct Agent {
    process: Child,
    pub socket: PathBuf,
}

impl Sshd {
    /// Start a server with the default test configuration.
    pub fn start() -> Self {
        Self::start_with(&[])
    }

    /// Start a server, passing `options` to sshd as `-o` settings.
    pub fn start_with(options: &[&str]) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("jato-it-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        keygen(&dir.join("id_plain"), "ed25519", "");
        keygen(&dir.join("id_encrypted"), "ed25519", PASSPHRASE);
        keygen(&dir.join("id_rsa"), "rsa", "");
        let authorized = [
            fs::read_to_string(dir.join("id_plain.pub")).unwrap(),
            fs::read_to_string(dir.join("id_encrypted.pub")).unwrap(),
            fs::read_to_string(dir.join("id_rsa.pub")).unwrap(),
        ]
        .concat();
        fs::write(dir.join("authorized_keys"), authorized).unwrap();

        let mut sshd = String::from("ssh-keygen -A && exec /usr/sbin/sshd -D -e");
        for option in options {
            sshd.push_str(&format!(" -o {option}"));
        }
        let mount = format!(
            "{}:/home/{USER}/.ssh/authorized_keys:ro",
            dir.join("authorized_keys").display()
        );
        let container = docker(&[
            "run",
            "-d",
            "--rm",
            "-p",
            "127.0.0.1::22",
            "-v",
            &mount,
            IMAGE,
            "/bin/sh",
            "-c",
            &sshd,
        ]);
        let port = docker(&["port", &container, "22/tcp"])
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        wait_for_banner(port);
        let host_key = read_file(&container, "/etc/ssh/ssh_host_ed25519_key.pub");
        let rsa_host_key = read_file(&container, "/etc/ssh/ssh_host_rsa_key.pub");
        Self {
            container,
            port,
            dir,
            host_key,
            rsa_host_key,
        }
    }

    /// A `known_hosts` file recording this server's ed25519 key.
    pub fn known_hosts(&self) -> PathBuf {
        self.known_hosts_with(&self.host_key)
    }

    /// A `known_hosts` file recording `key` for this server.
    pub fn known_hosts_with(&self, key: &str) -> PathBuf {
        let path = self.dir.join("known_hosts");
        fs::write(&path, format!("[127.0.0.1]:{} {key}\n", self.port)).unwrap();
        path
    }

    /// Start an ssh-agent holding the unencrypted test key.
    pub fn agent(&self) -> Agent {
        let socket = self.dir.join("agent.sock");
        let process = Command::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(&socket)
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !socket.exists() {
            assert!(Instant::now() < deadline, "ssh-agent did not start");
            std::thread::sleep(Duration::from_millis(20));
        }
        let status = Command::new("ssh-add")
            .arg("-q")
            .arg(self.dir.join("id_plain"))
            .env("SSH_AUTH_SOCK", &socket)
            .status()
            .unwrap();
        assert!(status.success());
        Agent { process, socket }
    }
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.container])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

fn keygen(path: &Path, key_type: &str, passphrase: &str) {
    let status = Command::new("ssh-keygen")
        .args([
            "-q",
            "-t",
            key_type,
            "-N",
            passphrase,
            "-C",
            "jato-test",
            "-f",
        ])
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success());
}

fn read_file(container: &str, path: &str) -> String {
    docker(&["exec", container, "cat", path])
}

fn docker(args: &[&str]) -> String {
    let output = Command::new("docker").args(args).output().unwrap();
    assert!(
        output.status.success(),
        "docker {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

/// Wait until sshd sends its version banner; the published port accepts connections earlier.
fn wait_for_banner(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut banner = [0; 4];
            if stream.read_exact(&mut banner).is_ok() && &banner == b"SSH-" {
                return;
            }
        }
        assert!(
            Instant::now() < deadline,
            "sshd on port {port} did not start"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}
