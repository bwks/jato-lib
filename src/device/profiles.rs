use crate::device::profile::{ConfigMode, DeviceProfile};
use crate::error::Error;
use crate::shell::Prompt;

/// A Cisco or Arista prompt in any mode: the hostname, a configuration sub-mode, then `>` or
/// `#`.
const CISCO_PROMPT: &str = r"(?P<base>\S+?)(\(config[^)]*\))?[>#] ?";
/// A Junos prompt in either mode: `user@host`, then `>` or `#`.
const JUNOS_PROMPT: &str = r"(?P<base>[^\s@>#]+@[^\s>#]+)[>#] ?";
/// The steady prompt `posix_shell` sets, without its `$` or `#`.
const POSIX_PROMPT_BASE: &str = "[jato]";
/// Password prompts, as most devices word them.
const PASSWORD_PROMPT: &str = r"[Pp]assword: ?";
/// Password prompts from `sudo` and `doas`, such as `[sudo] password for user: ` and
/// `doas (user@host) password: `.
const SHELL_PASSWORD_PROMPT: &str = r".*[Pp]assword.*: ?";

impl DeviceProfile {
    /// Cisco IOS and IOS XE.
    ///
    /// # Errors
    ///
    /// None in practice; the built-in patterns are valid.
    pub fn cisco_ios() -> Result<Self, Error> {
        Ok(Self {
            name: "cisco_ios".into(),
            prompt_pattern: CISCO_PROMPT.into(),
            prompt_setup: None,
            user_prompt: Some("{base}>".into()),
            privileged_prompt: "{base}#".into(),
            password_prompt: Prompt::new(PASSWORD_PROMPT)?,
            confirm_prompt: Prompt::new(r".*\[confirm\]\s*")?,
            confirm_answer: String::new(),
            decline_answer: "n".into(),
            setup_commands: vec!["terminal length 0".into(), "terminal width 511".into()],
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
        })
    }

    /// Cisco NX-OS.
    ///
    /// # Errors
    ///
    /// None in practice; the built-in patterns are valid.
    pub fn cisco_nxos() -> Result<Self, Error> {
        Ok(Self {
            name: "cisco_nxos".into(),
            prompt_pattern: CISCO_PROMPT.into(),
            prompt_setup: None,
            user_prompt: Some("{base}> ?".into()),
            privileged_prompt: "{base}# ?".into(),
            password_prompt: Prompt::new(PASSWORD_PROMPT)?,
            confirm_prompt: Prompt::new(r".*\(y/n\)\??\s*(\[[yn]\])?\s*")?,
            confirm_answer: "y".into(),
            decline_answer: "n\n".into(),
            setup_commands: vec!["terminal length 0".into(), "terminal width 511".into()],
            enable_command: Some("enable".into()),
            enable_starts_shell: false,
            disable_command: None,
            config: Some(ConfigMode::new(
                r"{base}\(config[^)]*\)# ?",
                "configure terminal",
                "end",
            )),
            error_markers: vec!["% ".into(), "ERROR: ".into()],
            status_command: None,
        })
    }

    /// Arista EOS.
    ///
    /// # Errors
    ///
    /// None in practice; the built-in patterns are valid.
    pub fn arista_eos() -> Result<Self, Error> {
        Ok(Self {
            name: "arista_eos".into(),
            prompt_pattern: CISCO_PROMPT.into(),
            prompt_setup: None,
            user_prompt: Some("{base}>".into()),
            privileged_prompt: "{base}#".into(),
            password_prompt: Prompt::new(PASSWORD_PROMPT)?,
            confirm_prompt: Prompt::new(r".*\[confirm\]\s*")?,
            confirm_answer: String::new(),
            decline_answer: "n".into(),
            setup_commands: vec!["terminal length 0".into(), "terminal width 32767".into()],
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
        })
    }

    /// Juniper Junos. Operational mode (`user@host>`) counts as
    /// [`Mode::Privileged`](crate::Mode::Privileged), as Junos has no enable step.
    /// Configuration is committed at the end of
    /// [`Device::send_config`](crate::Device::send_config), and thrown away if a line fails.
    ///
    /// # Errors
    ///
    /// None in practice; the built-in patterns are valid.
    pub fn juniper_junos() -> Result<Self, Error> {
        let mut config = ConfigMode::new("{base}# ?", "configure", "exit configuration-mode");
        config.commit_command = Some("commit".into());
        config.discard_command = Some("rollback 0".into());
        Ok(Self {
            name: "juniper_junos".into(),
            prompt_pattern: JUNOS_PROMPT.into(),
            prompt_setup: None,
            user_prompt: None,
            privileged_prompt: "{base}> ?".into(),
            password_prompt: Prompt::new(PASSWORD_PROMPT)?,
            confirm_prompt: Prompt::new(r".*\[yes,no\]\s*(\((yes|no)\))?\s*")?,
            confirm_answer: "yes".into(),
            decline_answer: "no\n".into(),
            setup_commands: vec![
                "set cli screen-length 0".into(),
                "set cli screen-width 1024".into(),
                "set cli complete-on-space off".into(),
            ],
            enable_command: None,
            enable_starts_shell: false,
            disable_command: None,
            config: Some(config),
            error_markers: vec![
                "error: ".into(),
                "syntax error".into(),
                "unknown command".into(),
                "missing argument".into(),
            ],
            status_command: None,
        })
    }

    /// A POSIX shell on Linux or BSD: `sh`, `ash`, `ksh`, `bash` or `zsh`. The prompt is set to
    /// `[jato]$ `, or `[jato]# ` for root, so it does not change with the working directory.
    /// Shells mark errors only by exit status, so after each command `echo $?` is run, and a
    /// status other than 0 is an error. There is no configuration mode.
    ///
    /// [`Device::enable`](crate::Device::enable) runs `sudo -s`, giving the user's password if
    /// asked; for `doas`, as on OpenBSD and Alpine, set `enable_command` to `doas -s`. The root
    /// shell gets the steady prompt too, as `[jato]# `.
    /// [`Device::disable`](crate::Device::disable) leaves it with `exit`.
    ///
    /// # Errors
    ///
    /// None in practice; the built-in patterns are valid.
    pub fn posix_shell() -> Result<Self, Error> {
        let base = POSIX_PROMPT_BASE;
        Ok(Self {
            name: "posix_shell".into(),
            prompt_pattern: r"(?P<base>\[jato\])[$#] ".into(),
            prompt_setup: Some(format!(
                r#"unset PROMPT_COMMAND; if [ "$(id -u)" = 0 ]; then PS1='{base}# '; else PS1='{base}$ '; fi"#
            )),
            user_prompt: Some(r"{base}\$ ".into()),
            privileged_prompt: "{base}# ".into(),
            password_prompt: Prompt::new(SHELL_PASSWORD_PROMPT)?,
            confirm_prompt: Prompt::new(r".*\[[yY]/[nN]\]\s*")?,
            confirm_answer: "y".into(),
            decline_answer: "n\n".into(),
            setup_commands: Vec::new(),
            enable_command: Some("sudo -s".into()),
            enable_starts_shell: true,
            disable_command: Some("exit".into()),
            config: None,
            error_markers: Vec::new(),
            status_command: Some("echo $?".into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::device::profile::{Mode, ModePrompts};

    use super::*;

    fn prompts(profile: &DeviceProfile, discovered: &str) -> ModePrompts {
        ModePrompts::from_prompt(profile, discovered).unwrap()
    }

    #[test]
    fn ios_prompts_come_from_the_discovered_one() {
        let ios = DeviceProfile::cisco_ios().unwrap();
        let modes = prompts(&ios, "router1#");
        assert_eq!(modes.mode_of("router1>"), Some(Mode::User));
        assert_eq!(modes.mode_of("router1#"), Some(Mode::Privileged));
        assert_eq!(
            modes.mode_of("router1(config-router-af)#"),
            Some(Mode::Config)
        );
        assert_eq!(modes.mode_of("router2#"), None);
        assert_eq!(modes.mode_of("Password: "), None);
    }

    #[test]
    fn ios_errors_and_confirmations() {
        let ios = DeviceProfile::cisco_ios().unwrap();
        assert_eq!(
            ios.error_in("interface Gi0/9\n         ^\n% Invalid input detected at '^' marker."),
            Some("% Invalid input detected at '^' marker.")
        );
        assert_eq!(ios.error_in("Building configuration...\n[OK]"), None);
        assert!(ios.confirm_prompt.matches(
            "This operation will remove all username related configurations with same name.Do you want to continue? [confirm]"
        ));
        assert!(ios.confirm_prompt.matches("Proceed with reload? [confirm]"));
    }

    #[test]
    fn nxos_prompts_and_confirmations() {
        let nxos = DeviceProfile::cisco_nxos().unwrap();
        let modes = prompts(&nxos, "nxos01# ");
        assert_eq!(modes.mode_of("nxos01# "), Some(Mode::Privileged));
        assert_eq!(modes.mode_of("nxos01(config-if)# "), Some(Mode::Config));
        assert!(
            nxos.confirm_prompt
                .matches("Do you want to continue? (y/n) [n] ")
        );
        assert_eq!(
            nxos.error_in("              ^\n% Invalid command at '^' marker."),
            Some("% Invalid command at '^' marker.")
        );
    }

    #[test]
    fn eos_prompts_come_from_the_discovered_one() {
        let eos = DeviceProfile::arista_eos().unwrap();
        let modes = prompts(&eos, "eos01>");
        assert_eq!(modes.mode_of("eos01#"), Some(Mode::Privileged));
        assert_eq!(modes.mode_of("eos01(config-if-Et1)#"), Some(Mode::Config));
    }

    #[test]
    fn junos_prompts_and_errors() {
        let junos = DeviceProfile::juniper_junos().unwrap();
        let modes = prompts(&junos, "sherpa@junos01> ");
        assert_eq!(modes.mode_of("sherpa@junos01> "), Some(Mode::Privileged));
        assert_eq!(modes.mode_of("sherpa@junos01# "), Some(Mode::Config));
        assert_eq!(modes.mode_of("[edit]"), None);
        assert_eq!(modes.mode_of("other@junos01> "), None);
        assert_eq!(
            junos.error_in("                  ^\nsyntax error."),
            Some("syntax error.")
        );
        assert_eq!(junos.error_in("warning: statement has no effect"), None);
        assert!(
            junos
                .confirm_prompt
                .matches("Exit with uncommitted changes? [yes,no] (yes) ")
        );
    }

    #[test]
    fn posix_prompts_are_the_ones_it_sets() {
        let posix = DeviceProfile::posix_shell().unwrap();
        let modes = prompts(&posix, "[jato]$ ");
        assert_eq!(modes.mode_of("[jato]$ "), Some(Mode::User));
        assert_eq!(modes.mode_of("[jato]# "), Some(Mode::Privileged));
        assert_eq!(modes.mode_of("sherpa@ubuntu01:~$ "), None);
        assert!(posix.config.is_none());
        assert!(
            posix
                .password_prompt
                .matches("[sudo] password for sherpa: ")
        );
        assert!(
            posix
                .password_prompt
                .matches("doas (sherpa@openbsd01) password: ")
        );
        assert!(ModePrompts::from_prompt(&posix, "sherpa@ubuntu01:~$ ").is_err());
    }
}
