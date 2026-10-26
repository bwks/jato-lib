use regex::Regex;

use crate::shared::error::Error;
use crate::ssh::shell::Prompt;

/// The placeholder for the discovered prompt's base in a prompt template.
const BASE_PLACEHOLDER: &str = "{base}";
/// The name of the capture group holding the base in a prompt pattern.
const BASE_GROUP: &str = "base";

/// The CLI mode a device is in, as its prompt shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Mode {
    /// Unprivileged mode, such as `router>`, or an ordinary user's shell.
    User,
    /// Privileged exec mode, such as `router#`, a device's only operational mode, such as
    /// Junos `user@router>`, or a root shell.
    Privileged,
    /// Configuration mode or one of its sub-modes, such as `router(config-if)#`.
    Config,
}

/// How to drive one kind of device's CLI. The built-in profiles are made by functions such
/// as [`DeviceProfile::cisco_ios`].
///
/// Prompts are found on the device, not assumed: `prompt_pattern` splits the discovered
/// prompt into a `base` (such as the hostname, or `user@host` on Junos), and each mode's
/// prompt is a template in which `{base}` stands for that base, matched literally.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct DeviceProfile {
    /// The profile's name, for logs.
    pub name: String,
    /// A pattern matching the device's prompt in any mode, whole, with a named group `base`.
    pub prompt_pattern: String,
    /// A command that sets a steady prompt, run before the prompt is discovered, for shells
    /// whose prompt otherwise changes with the working directory.
    pub prompt_setup: Option<String>,
    /// The prompt template in unprivileged mode, for devices that have one.
    pub user_prompt: Option<String>,
    /// The prompt template in privileged mode, or the only operational mode.
    pub privileged_prompt: String,
    /// The prompt asking for a password, such as after `enable`.
    pub password_prompt: Prompt,
    /// The prompt asking to confirm an action, such as `... [confirm]`.
    pub confirm_prompt: Prompt,
    /// What to send to confirm, followed by a newline.
    pub confirm_answer: String,
    /// What to send to decline, without a newline.
    pub decline_answer: String,
    /// Commands run once the prompt is known, such as turning off paging.
    pub setup_commands: Vec<String>,
    /// The command that enters privileged mode, for devices with a user mode.
    pub enable_command: Option<String>,
    /// Whether the enable command starts a new shell with a prompt of its own, as `sudo -s`
    /// does. If so, the prompt setup runs again and the prompt is discovered again.
    pub enable_starts_shell: bool,
    /// The command that leaves privileged mode for user mode, such as `exit` from a root
    /// shell.
    pub disable_command: Option<String>,
    /// Configuration mode, for devices that have one.
    pub config: Option<ConfigMode>,
    /// Output lines that start with one of these mean the command failed.
    pub error_markers: Vec<String>,
    /// A command that prints the last command's exit status, such as `echo $?` in a shell.
    /// After each command it is run, and a status other than 0 means the command failed.
    pub status_command: Option<String>,
}

/// How a device's configuration mode works.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ConfigMode {
    /// The prompt template in configuration mode and its sub-modes.
    pub prompt: String,
    /// The command that enters configuration mode from privileged mode.
    pub enter_command: String,
    /// The command that leaves configuration mode for privileged mode.
    pub end_command: String,
    /// The command that makes changes take effect, for devices that need one, such as
    /// Junos `commit`.
    pub commit_command: Option<String>,
    /// The command that throws away changes not yet committed, run when a line fails on a
    /// device with a commit command.
    pub discard_command: Option<String>,
}

/// One device's prompts in each mode, made from its discovered prompt.
#[derive(Clone, Debug)]
pub(crate) struct ModePrompts {
    pub(crate) user: Option<Prompt>,
    pub(crate) privileged: Prompt,
    pub(crate) config: Option<Prompt>,
}

impl ConfigMode {
    /// Configuration mode entered with `enter_command` and left with `end_command`, with
    /// prompts made from `prompt`, a template.
    pub fn new(prompt: &str, enter_command: &str, end_command: &str) -> Self {
        Self {
            prompt: prompt.to_string(),
            enter_command: enter_command.to_string(),
            end_command: end_command.to_string(),
            commit_command: None,
            discard_command: None,
        }
    }
}

impl DeviceProfile {
    /// The first line of `output` that reports an error, if any.
    pub(crate) fn error_in<'a>(&self, output: &'a str) -> Option<&'a str> {
        output.lines().find(|line| {
            self.error_markers
                .iter()
                .any(|marker| line.starts_with(marker.as_str()))
        })
    }
}

impl ModePrompts {
    /// The prompts for each mode of `profile`, from `discovered`, the prompt the device
    /// showed.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPrompt`] if `discovered` does not match the profile's prompt pattern,
    /// or a pattern is not valid.
    pub(crate) fn from_prompt(profile: &DeviceProfile, discovered: &str) -> Result<Self, Error> {
        let pattern =
            Regex::new(&format!("^(?:{})$", profile.prompt_pattern)).map_err(|error| {
                Error::InvalidPrompt {
                    pattern: profile.prompt_pattern.clone(),
                    message: error.to_string(),
                }
            })?;
        let base = pattern
            .captures(discovered)
            .and_then(|captures| captures.name(BASE_GROUP))
            .ok_or_else(|| Error::InvalidPrompt {
                pattern: profile.prompt_pattern.clone(),
                message: format!(
                    "the device's prompt {discovered:?} does not look like a {} prompt",
                    profile.name
                ),
            })?;
        let base = regex::escape(base.as_str());
        let user = match &profile.user_prompt {
            Some(template) => Some(prompt_from(template, &base)?),
            None => None,
        };
        let config = match &profile.config {
            Some(config) => Some(prompt_from(&config.prompt, &base)?),
            None => None,
        };
        Ok(Self {
            user,
            privileged: prompt_from(&profile.privileged_prompt, &base)?,
            config,
        })
    }

    /// The mode `line`, a prompt, shows, if it is one of these prompts.
    pub(crate) fn mode_of(&self, line: &str) -> Option<Mode> {
        if self
            .config
            .as_ref()
            .is_some_and(|prompt| prompt.matches(line))
        {
            Some(Mode::Config)
        } else if self.privileged.matches(line) {
            Some(Mode::Privileged)
        } else if self
            .user
            .as_ref()
            .is_some_and(|prompt| prompt.matches(line))
        {
            Some(Mode::User)
        } else {
            None
        }
    }

    /// A prompt matching any mode.
    pub(crate) fn any(&self) -> Result<Prompt, Error> {
        let mut prompts = vec![&self.privileged];
        prompts.extend(self.user.as_ref());
        prompts.extend(self.config.as_ref());
        Prompt::any_of(&prompts)
    }
}

/// The prompt `template` describes, with `base` (already escaped) in place of `{base}`.
fn prompt_from(template: &str, base: &str) -> Result<Prompt, Error> {
    Prompt::new(&template.replace(BASE_PLACEHOLDER, base))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cisco_like() -> DeviceProfile {
        DeviceProfile {
            name: "test".into(),
            prompt_pattern: r"(?P<base>\S+?)(\(config[^)]*\))?[>#]".into(),
            prompt_setup: None,
            user_prompt: Some("{base}>".into()),
            privileged_prompt: "{base}#".into(),
            password_prompt: Prompt::new("Password: ?").unwrap(),
            confirm_prompt: Prompt::new(r".*\[confirm\]").unwrap(),
            confirm_answer: String::new(),
            decline_answer: "n".into(),
            setup_commands: Vec::new(),
            enable_command: Some("enable".into()),
            enable_starts_shell: false,
            disable_command: None,
            config: Some(ConfigMode::new(
                r"{base}\(config[^)]*\)#",
                "configure terminal",
                "end",
            )),
            error_markers: vec!["% ".into()],
            status_command: None,
        }
    }

    #[test]
    fn mode_prompts_use_the_discovered_base() {
        let prompts = ModePrompts::from_prompt(&cisco_like(), "core.lab-1#").unwrap();
        assert_eq!(prompts.mode_of("core.lab-1#"), Some(Mode::Privileged));
        assert_eq!(prompts.mode_of("core.lab-1>"), Some(Mode::User));
        assert_eq!(
            prompts.mode_of("core.lab-1(config-if)#"),
            Some(Mode::Config)
        );
        assert_eq!(prompts.mode_of("other#"), None);
        assert_eq!(prompts.mode_of("core.lab-1# show"), None);
    }

    #[test]
    fn the_base_is_matched_literally() {
        let prompts = ModePrompts::from_prompt(&cisco_like(), "r1.lab>").unwrap();
        assert_eq!(prompts.mode_of("r1.lab#"), Some(Mode::Privileged));
        assert_eq!(prompts.mode_of("r1xlab#"), None);
    }

    #[test]
    fn a_prompt_from_config_mode_gives_the_same_base() {
        let prompts = ModePrompts::from_prompt(&cisco_like(), "r1(config)#").unwrap();
        assert_eq!(prompts.mode_of("r1#"), Some(Mode::Privileged));
    }

    #[test]
    fn a_prompt_that_does_not_fit_the_profile_is_refused() {
        let error = ModePrompts::from_prompt(&cisco_like(), "[jato]$ ").unwrap_err();
        assert!(error.to_string().contains("[jato]$ "), "{error}");
    }

    #[test]
    fn devices_without_user_or_config_modes() {
        let mut profile = cisco_like();
        profile.user_prompt = None;
        profile.config = None;
        let prompts = ModePrompts::from_prompt(&profile, "r1#").unwrap();
        assert_eq!(prompts.mode_of("r1>"), None);
        assert_eq!(prompts.mode_of("r1(config)#"), None);
        assert_eq!(prompts.mode_of("r1#"), Some(Mode::Privileged));
    }

    #[test]
    fn errors_are_found_by_marker() {
        let profile = cisco_like();
        assert_eq!(
            profile.error_in("x\n% Invalid input detected at '^' marker."),
            Some("% Invalid input detected at '^' marker.")
        );
        assert_eq!(profile.error_in("  100% done"), None);
    }
}
