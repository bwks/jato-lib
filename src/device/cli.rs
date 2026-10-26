use std::time::Duration;

use crate::connect::Session;
use crate::device::profile::{DeviceProfile, Mode, ModePrompts};
use crate::error::Error;
use crate::node::Node;
use crate::secret::Secret;
use crate::shell::{Prompt, Shell, ShellOptions, command_output, last_line};

/// The time limit for each command by default.
const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
/// How long output must pause, by default, before Jato takes it as finished when the prompt
/// is not known yet.
const DEFAULT_QUIET_AFTER: Duration = Duration::from_millis(500);
/// The most confirmations one configuration line may ask for before Jato gives up.
const MAX_CONFIRMATIONS: usize = 3;
/// The most password prompts answered with nothing, after a refused enable secret, before
/// Jato gives up waiting for the device to return to a mode prompt.
const MAX_PASSWORD_CANCELS: usize = 5;

/// Settings for a device CLI session.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct DeviceOptions {
    /// The time limit for each command, 30 seconds by default.
    pub command_timeout: Duration,
    /// How long output must pause before it is taken as finished while the prompt is being
    /// discovered, 500 milliseconds by default. Raise it for devices slow to answer.
    pub quiet_after: Duration,
}

/// A device CLI, driven through a [`Shell`] with a [`DeviceProfile`].
pub struct Device {
    node: Node,
    shell: Shell,
    profile: DeviceProfile,
    options: DeviceOptions,
    mode: Mode,
    /// The prompt in each mode, from the discovered prompt.
    prompts: ModePrompts,
    /// Any of the mode prompts.
    any_prompt: Prompt,
    /// Any mode prompt, or the password prompt.
    any_or_password: Prompt,
    /// Any mode prompt, or the confirmation prompt.
    any_or_confirm: Prompt,
}

impl Default for DeviceOptions {
    fn default() -> Self {
        Self {
            command_timeout: DEFAULT_COMMAND_TIMEOUT,
            quiet_after: DEFAULT_QUIET_AFTER,
        }
    }
}

impl Device {
    /// Open a shell on `session` and get the CLI ready: read past the login banner, run the
    /// profile's prompt setup if it has one, discover the prompt, work out the prompt for
    /// each mode from it, note the mode, and run the profile's setup commands.
    ///
    /// # Errors
    ///
    /// [`Error::PromptNotDiscovered`] if no steady prompt appears, [`Error::InvalidPrompt`] if
    /// the prompt does not fit the profile, [`Error::DeviceCommand`] if a setup command fails,
    /// and as for [`Session::shell`].
    #[tracing::instrument(skip_all, fields(node = %session.node(), profile = %profile.name))]
    pub async fn open(
        session: &Session,
        profile: DeviceProfile,
        options: DeviceOptions,
    ) -> Result<Self, Error> {
        let mut shell = session.shell(&ShellOptions::default()).await?;
        let (idle, timeout) = (options.quiet_after, options.command_timeout);
        shell.read_until_quiet(idle, timeout).await?;
        if let Some(setup) = &profile.prompt_setup {
            shell.send_line(setup).await?;
            shell.read_until_quiet(idle, timeout).await?;
        }
        let discovered = shell.discover_prompt(idle, timeout).await?;
        let prompts = ModePrompts::from_prompt(&profile, &discovered)?;
        let Some(mode) = prompts.mode_of(&discovered) else {
            return Err(Error::InvalidPrompt {
                pattern: profile.prompt_pattern.clone(),
                message: format!(
                    "the device's prompt {discovered:?} is not one of the {} mode prompts",
                    profile.name
                ),
            });
        };
        let any_prompt = prompts.any()?;
        let any_or_password = Prompt::any_of(&[&any_prompt, &profile.password_prompt])?;
        let any_or_confirm = Prompt::any_of(&[&any_prompt, &profile.confirm_prompt])?;
        let mut device = Self {
            node: session.node().clone(),
            shell,
            profile,
            options,
            mode,
            prompts,
            any_prompt,
            any_or_password,
            any_or_confirm,
        };
        let setup = device.profile.setup_commands.clone();
        for command in &setup {
            device.send_command(command).await?;
        }
        tracing::debug!(prompt = %discovered, mode = ?device.mode, "device ready");
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
    /// [`Error::DeviceCommand`] if the output reports an error, the command exits with a
    /// status other than 0 (on profiles with a status command), or it asks for
    /// confirmation, and as for [`Shell::read_until`].
    #[tracing::instrument(skip_all, fields(node = %self.node), level = "debug")]
    pub async fn send_command(&mut self, command: &str) -> Result<String, Error> {
        let output = self.exchange(command, false).await?;
        if let Some(message) = self.profile.error_in(&output) {
            return Err(self.failure("command", message));
        }
        if let Some(status) = self.exit_status().await?
            && status != 0
        {
            let last = output.lines().last().unwrap_or_default();
            return Err(self.failure("command", &format!("exit status {status}: {last}")));
        }
        Ok(output)
    }

    /// Enter privileged mode, giving `secret` if the device asks for a password. Does nothing
    /// if the device is already privileged.
    ///
    /// # Errors
    ///
    /// [`Error::DeviceCommand`] if the device refuses or its profile has no enable command,
    /// and as for [`Shell::read_until`].
    #[tracing::instrument(skip_all, fields(node = %self.node))]
    pub async fn enable(&mut self, secret: &Secret) -> Result<(), Error> {
        if self.mode != Mode::User {
            return Ok(());
        }
        let Some(command) = self.profile.enable_command.clone() else {
            return Err(self.failure("enable", "this device has no enable command"));
        };
        self.shell.send_line(&command).await?;
        let mut received = self
            .shell
            .read_after_echo(
                &self.any_or_password,
                &command,
                self.options.command_timeout,
            )
            .await?;
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

    /// Enter configuration mode, send each of `lines`, commit them if the device needs it,
    /// and return to privileged mode. Stops at the first line the device reports an error
    /// for; on a device that commits, the uncommitted changes are then thrown away. Either
    /// way configuration mode is left. Returns the output of all the lines, joined.
    ///
    /// A line that asks for confirmation, such as `no username`, is confirmed: sending it
    /// is the request.
    ///
    /// # Errors
    ///
    /// [`Error::DeviceCommand`] naming the line that failed (by number, not its text), or if
    /// the device has no configuration mode or is not privileged, and as for
    /// [`Shell::read_until`].
    #[tracing::instrument(skip_all, fields(node = %self.node, lines = lines.len()))]
    pub async fn send_config(&mut self, lines: &[&str]) -> Result<String, Error> {
        let Some(config) = self.profile.config.clone() else {
            return Err(self.failure("configuration", "this device has no configuration mode"));
        };
        if self.mode == Mode::User {
            return Err(self.failure("configuration", "the device is not in privileged mode"));
        }
        if self.mode == Mode::Privileged {
            let output = self.send_command(&config.enter_command).await?;
            if self.mode != Mode::Config {
                let shown = output.lines().last().unwrap_or_default();
                return Err(self.failure(
                    "configuration",
                    &format!("the device did not enter config mode; it said {shown:?}"),
                ));
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
        if failure.is_none()
            && let Some(commit) = &config.commit_command
        {
            let output = self.exchange(commit, true).await?;
            match self.profile.error_in(&output) {
                Some(message) => failure = Some(self.failure("commit", message)),
                None => outputs.push(output),
            }
        }
        if failure.is_some()
            && let Some(discard) = &config.discard_command
        {
            self.exchange(discard, true).await?;
        }
        self.exchange(&config.end_command, true).await?;
        match failure {
            Some(error) => Err(error),
            None => Ok(outputs.join("\n").trim_matches('\n').to_string()),
        }
    }

    /// The exit status of the last command, for profiles with a status command.
    async fn exit_status(&mut self) -> Result<Option<i32>, Error> {
        let Some(command) = self.profile.status_command.clone() else {
            return Ok(None);
        };
        let output = self.exchange(&command, false).await?;
        match output.trim().parse() {
            Ok(status) => Ok(Some(status)),
            Err(_) => Err(self.failure(
                "command",
                &format!("could not read the exit status from {output:?}"),
            )),
        }
    }

    /// Send `command`, read until any mode prompt once its echo has arrived, note the mode,
    /// and return the output. A confirmation prompt is answered yes if `confirm`, else
    /// declined with an error.
    async fn exchange(&mut self, command: &str, confirm: bool) -> Result<String, Error> {
        self.shell.send_line(command).await?;
        let mut received = self
            .shell
            .read_after_echo(&self.any_or_confirm, command, self.options.command_timeout)
            .await?;
        for _ in 0..MAX_CONFIRMATIONS {
            if !self.profile.confirm_prompt.matches(&last_line(&received)) {
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
            let more = self
                .shell
                .read_until(&self.any_or_confirm, self.options.command_timeout)
                .await?;
            received.push_str(&more);
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
        for _ in 0..MAX_PASSWORD_CANCELS {
            self.shell.send_line("").await?;
            let received = self.read_any_or_password().await?;
            if !self.profile.password_prompt.matches(&last_line(&received)) {
                self.mode = self.mode_shown(&received);
                return Ok(());
            }
        }
        Err(self.failure(
            "enable",
            "the device kept asking for a password after the secret was refused",
        ))
    }

    /// The mode the prompt at the end of `received` shows, or the current mode if it shows
    /// none.
    fn mode_shown(&self, received: &str) -> Mode {
        self.prompts
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
