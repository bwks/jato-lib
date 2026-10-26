use std::time::Duration;

use crate::connect::Session;
use crate::error::Error;
use crate::node::Node;
use crate::secret::Secret;
use crate::shell::{Prompt, Shell, ShellOptions, command_output, last_line};

/// The time limit for each command by default.
const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
/// The most confirmations one configuration line may ask for before Jato gives up.
const MAX_CONFIRMATIONS: usize = 3;
/// Characters a Cisco hostname prompt may use.
const CISCO_HOSTNAME: &str = r"[\w.\-@/:]{1,63}";

/// The CLI mode a device is in, as its prompt shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Mode {
    /// Unprivileged exec mode, such as `router>`.
    User,
    /// Privileged exec mode, such as `router#`.
    Privileged,
    /// Configuration mode or one of its sub-modes, such as `router(config-if)#`.
    Config,
}

/// How to drive one kind of device's CLI.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct DeviceProfile {
    /// The profile's name, for logs.
    pub name: String,
    /// The prompt in unprivileged exec mode.
    pub user_prompt: Prompt,
    /// The prompt in privileged exec mode.
    pub privileged_prompt: Prompt,
    /// The prompt in configuration mode and its sub-modes.
    pub config_prompt: Prompt,
    /// The prompt asking for a password, such as after `enable`.
    pub password_prompt: Prompt,
    /// The prompt asking to confirm an action, such as `... [confirm]`.
    pub confirm_prompt: Prompt,
    /// What to send to confirm, followed by a newline.
    pub confirm_answer: String,
    /// What to send to decline, without a newline.
    pub decline_answer: String,
    /// Commands run after logging in, such as turning off paging.
    pub setup_commands: Vec<String>,
    /// The command that enters privileged mode.
    pub enable_command: String,
    /// The command that enters configuration mode from privileged mode.
    pub config_command: String,
    /// The command that leaves configuration mode for privileged mode.
    pub end_config_command: String,
    /// Output lines that start with one of these mean the command failed.
    pub error_markers: Vec<String>,
}

/// Settings for a device CLI session.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct DeviceOptions {
    /// The time limit for each command, 30 seconds by default.
    pub command_timeout: Duration,
}

/// A device CLI, driven through a [`Shell`] with a [`DeviceProfile`].
pub struct Device {
    node: Node,
    shell: Shell,
    profile: DeviceProfile,
    options: DeviceOptions,
    mode: Mode,
    /// Any of the profile's mode prompts.
    any_prompt: Prompt,
    /// Any mode prompt, or the password prompt.
    any_or_password: Prompt,
    /// Any mode prompt, or the confirmation prompt.
    any_or_confirm: Prompt,
}

impl DeviceProfile {
    /// Cisco IOS and IOS XE.
    ///
    /// # Errors
    ///
    /// None in practice; the built-in patterns are valid.
    pub fn cisco_ios() -> Result<Self, Error> {
        Ok(Self {
            name: "cisco_ios".into(),
            user_prompt: Prompt::new(&format!("{CISCO_HOSTNAME}>"))?,
            privileged_prompt: Prompt::new(&format!("{CISCO_HOSTNAME}#"))?,
            config_prompt: Prompt::new(&format!(r"{CISCO_HOSTNAME}\(config[^)]*\)#"))?,
            password_prompt: Prompt::new(r"[Pp]assword: ?")?,
            confirm_prompt: Prompt::new(r".*\[confirm\]\s*")?,
            confirm_answer: String::new(),
            decline_answer: "n".into(),
            setup_commands: vec!["terminal length 0".into(), "terminal width 511".into()],
            enable_command: "enable".into(),
            config_command: "configure terminal".into(),
            end_config_command: "end".into(),
            error_markers: vec!["% ".into()],
        })
    }

    /// The mode `line`, a prompt, shows, if it is one of this profile's prompts.
    fn mode_of(&self, line: &str) -> Option<Mode> {
        if self.config_prompt.matches(line) {
            Some(Mode::Config)
        } else if self.privileged_prompt.matches(line) {
            Some(Mode::Privileged)
        } else if self.user_prompt.matches(line) {
            Some(Mode::User)
        } else {
            None
        }
    }

    /// The first line of `output` that reports an error, if any.
    fn error_in<'a>(&self, output: &'a str) -> Option<&'a str> {
        output.lines().find(|line| {
            self.error_markers
                .iter()
                .any(|marker| line.starts_with(marker.as_str()))
        })
    }
}

impl Default for DeviceOptions {
    fn default() -> Self {
        Self {
            command_timeout: DEFAULT_COMMAND_TIMEOUT,
        }
    }
}

impl Device {
    /// Open a shell on `session` and get the CLI ready: wait for the first prompt, past any
    /// login banner, note the mode, and run the profile's setup commands.
    ///
    /// # Errors
    ///
    /// As for [`Session::shell`] and [`Shell::read_until`], and [`Error::DeviceCommand`] if a
    /// setup command fails.
    #[tracing::instrument(skip_all, fields(node = %session.node(), profile = %profile.name))]
    pub async fn open(
        session: &Session,
        profile: DeviceProfile,
        options: DeviceOptions,
    ) -> Result<Self, Error> {
        let any_prompt = Prompt::any_of(&[
            &profile.user_prompt,
            &profile.privileged_prompt,
            &profile.config_prompt,
        ])?;
        let any_or_password = Prompt::any_of(&[&any_prompt, &profile.password_prompt])?;
        let any_or_confirm = Prompt::any_of(&[&any_prompt, &profile.confirm_prompt])?;
        let mut shell = session.shell(&ShellOptions::default()).await?;
        let received = shell
            .read_until(&any_prompt, options.command_timeout)
            .await?;
        let mode = profile.mode_of(&last_line(&received)).unwrap_or(Mode::User);
        let mut device = Self {
            node: session.node().clone(),
            shell,
            profile,
            options,
            mode,
            any_prompt,
            any_or_password,
            any_or_confirm,
        };
        let setup = device.profile.setup_commands.clone();
        for command in &setup {
            device.send_command(command).await?;
        }
        tracing::debug!(mode = ?device.mode, "device ready");
        Ok(device)
    }

    /// The mode the device is in.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Run `command` and return its output, without the echoed command or the prompt.
    ///
    /// A command that asks for confirmation, such as `reload`, is declined, so it never goes
    /// ahead by accident.
    ///
    /// # Errors
    ///
    /// [`Error::DeviceCommand`] if the output reports an error or the command asks for
    /// confirmation, and as for [`Shell::read_until`].
    #[tracing::instrument(skip_all, fields(node = %self.node), level = "debug")]
    pub async fn send_command(&mut self, command: &str) -> Result<String, Error> {
        let output = self.exchange(command, false).await?;
        match self.profile.error_in(&output) {
            Some(message) => Err(self.failure("command", message)),
            None => Ok(output),
        }
    }

    /// Enter privileged mode, giving `secret` if the device asks for a password. Does nothing
    /// if the device is already privileged.
    ///
    /// # Errors
    ///
    /// [`Error::DeviceCommand`] if the device refuses, and as for [`Shell::read_until`].
    #[tracing::instrument(skip_all, fields(node = %self.node))]
    pub async fn enable(&mut self, secret: &Secret) -> Result<(), Error> {
        if self.mode != Mode::User {
            return Ok(());
        }
        let command = self.profile.enable_command.clone();
        self.shell.send_line(&command).await?;
        let mut received = self.read_any_or_password().await?;
        if self.profile.password_prompt.matches(&last_line(&received)) {
            self.shell.send_line(secret.expose()).await?;
            received = self.read_any_or_password().await?;
            if self.profile.password_prompt.matches(&last_line(&received)) {
                self.cancel_password_prompts().await?;
                return Err(self.failure("enable", "the enable secret was refused"));
            }
        }
        self.mode = self.mode_shown(&received);
        if self.mode != Mode::Privileged {
            let message = self
                .profile
                .error_in(&command_output(&received, &command))
                .unwrap_or("the device did not enter privileged mode")
                .to_string();
            return Err(self.failure("enable", &message));
        }
        Ok(())
    }

    /// Enter configuration mode, send each of `lines`, and return to privileged mode. Stops
    /// at the first line the device reports an error for, and still leaves configuration
    /// mode. Returns the output of all the lines, joined.
    ///
    /// A line that asks for confirmation, such as `no username`, is confirmed: sending it
    /// is the request.
    ///
    /// # Errors
    ///
    /// [`Error::DeviceCommand`] naming the line that failed (by number, not its text) or if
    /// the device is not privileged, and as for [`Shell::read_until`].
    #[tracing::instrument(skip_all, fields(node = %self.node, lines = lines.len()))]
    pub async fn send_config(&mut self, lines: &[&str]) -> Result<String, Error> {
        if self.mode == Mode::User {
            return Err(self.failure("configuration", "the device is not in privileged mode"));
        }
        if self.mode == Mode::Privileged {
            let command = self.profile.config_command.clone();
            self.send_command(&command).await?;
            if self.mode != Mode::Config {
                return Err(self.failure("configuration", "the device did not enter config mode"));
            }
        }
        let mut outputs = Vec::new();
        let mut failure = None;
        for (index, line) in lines.iter().enumerate() {
            let output = self.exchange(line, true).await?;
            if let Some(message) = self.profile.error_in(&output) {
                failure = Some(self.failure(&format!("config line {}", index + 1), message));
                break;
            }
            outputs.push(output);
        }
        let end = self.profile.end_config_command.clone();
        self.exchange(&end, false).await?;
        match failure {
            Some(error) => Err(error),
            None => Ok(outputs.join("\n").trim_matches('\n').to_string()),
        }
    }

    /// Send `command`, read until any mode prompt, note the mode, and return the output. A
    /// confirmation prompt is answered yes if `confirm`, else declined with an error.
    async fn exchange(&mut self, command: &str, confirm: bool) -> Result<String, Error> {
        self.shell.send_line(command).await?;
        let mut received = String::new();
        for _ in 0..=MAX_CONFIRMATIONS {
            let part = self
                .shell
                .read_until(&self.any_or_confirm, self.options.command_timeout)
                .await?;
            received.push_str(&part);
            if !self.profile.confirm_prompt.matches(&last_line(&part)) {
                self.mode = self.mode_shown(&received);
                return Ok(command_output(&received, command));
            }
            if !confirm {
                let decline = self.profile.decline_answer.clone();
                self.shell.send(&decline).await?;
                let rest = self
                    .shell
                    .read_until(&self.any_prompt, self.options.command_timeout)
                    .await?;
                self.mode = self.mode_shown(&rest);
                return Err(self.failure(
                    "command",
                    "the device asked for confirmation, which commands are not given",
                ));
            }
            let answer = self.profile.confirm_answer.clone();
            self.shell.send_line(&answer).await?;
        }
        Err(self.failure(
            "configuration",
            &format!("the device asked for confirmation more than {MAX_CONFIRMATIONS} times"),
        ))
    }

    /// Read until any mode prompt or the password prompt.
    async fn read_any_or_password(&mut self) -> Result<String, Error> {
        self.shell
            .read_until(&self.any_or_password, self.options.command_timeout)
            .await
    }

    /// Answer password prompts with nothing until the device gives up and shows a mode
    /// prompt.
    async fn cancel_password_prompts(&mut self) -> Result<(), Error> {
        loop {
            self.shell.send_line("").await?;
            let received = self.read_any_or_password().await?;
            if !self.profile.password_prompt.matches(&last_line(&received)) {
                self.mode = self.mode_shown(&received);
                return Ok(());
            }
        }
    }

    /// The mode the prompt at the end of `received` shows, or the current mode if it shows
    /// none.
    fn mode_shown(&self, received: &str) -> Mode {
        self.profile
            .mode_of(&last_line(received))
            .unwrap_or(self.mode)
    }

    /// An [`Error::DeviceCommand`] for `step`.
    fn failure(&self, step: &str, message: &str) -> Error {
        Error::DeviceCommand {
            node: self.node.clone(),
            step: step.to_string(),
            message: message.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ios() -> DeviceProfile {
        DeviceProfile::cisco_ios().unwrap()
    }

    #[test]
    fn ios_prompts_show_the_mode() {
        let ios = ios();
        assert_eq!(ios.mode_of("router1>"), Some(Mode::User));
        assert_eq!(ios.mode_of("router1#"), Some(Mode::Privileged));
        assert_eq!(ios.mode_of("router1(config)#"), Some(Mode::Config));
        assert_eq!(ios.mode_of("core-sw.lab(config-if)#"), Some(Mode::Config));
        assert_eq!(ios.mode_of("r1(config-router-af)#"), Some(Mode::Config));
        assert_eq!(ios.mode_of("Password: "), None);
        assert_eq!(ios.mode_of("router1# show"), None);
    }

    #[test]
    fn ios_confirmations_are_recognised() {
        let ios = ios();
        assert!(ios.confirm_prompt.matches(
            "This operation will remove all username related configurations with same name.Do you want to continue? [confirm]"
        ));
        assert!(ios.confirm_prompt.matches("Proceed with reload? [confirm]"));
        assert!(!ios.confirm_prompt.matches("router1#"));
        assert_eq!(ios.mode_of("Proceed with reload? [confirm]"), None);
    }

    #[test]
    fn ios_errors_are_found() {
        let ios = ios();
        let output = "interface Gi0/9\n         ^\n% Invalid input detected at '^' marker.";
        assert_eq!(
            ios.error_in(output),
            Some("% Invalid input detected at '^' marker.")
        );
        assert_eq!(
            ios.error_in("% Incomplete command."),
            Some("% Incomplete command.")
        );
        assert_eq!(ios.error_in("Building configuration...\n[OK]"), None);
        assert_eq!(ios.error_in("  100% done"), None);
    }
}
