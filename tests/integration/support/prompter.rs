//! A [`Prompter`] that answers from a script, for tests of asking for secrets and about
//! host keys.
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use jato::{Node, Prompter, Secret};

/// What a [`ScriptedPrompter`] was asked.
#[derive(Debug, PartialEq)]
pub enum Asked {
    Passphrase(PathBuf),
    Password(String),
    HostKey(String),
    Recorded(String, PathBuf),
}

/// Answers prompts from a script, in order, and records each question. `None` declines.
#[derive(Debug)]
pub struct ScriptedPrompter {
    answers: Mutex<VecDeque<Option<&'static str>>>,
    asked: Mutex<Vec<Asked>>,
}

impl ScriptedPrompter {
    pub fn new(answers: &[Option<&'static str>]) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers.iter().copied().collect()),
            asked: Mutex::new(Vec::new()),
        })
    }

    fn next(&self, asked: Asked) -> Option<Secret> {
        self.asked.lock().unwrap().push(asked);
        let answer = self.answers.lock().unwrap().pop_front().flatten()?;
        Some(Secret::new(answer.to_string()))
    }

    fn record(&self, asked: Asked) {
        self.asked.lock().unwrap().push(asked);
    }

    pub fn asked(&self) -> Vec<Asked> {
        std::mem::take(&mut *self.asked.lock().unwrap())
    }
}

impl Prompter for ScriptedPrompter {
    fn passphrase(&self, path: &Path) -> Option<Secret> {
        self.next(Asked::Passphrase(path.to_path_buf()))
    }

    fn password(&self, node: &Node, username: &str) -> Option<Secret> {
        self.next(Asked::Password(format!("{username}@{node}")))
    }

    fn confirm_host_key(&self, node: &Node, _fingerprint: &str) -> bool {
        match self.next(Asked::HostKey(node.to_string())) {
            Some(answer) => answer.expose() == "yes",
            None => false,
        }
    }

    fn host_key_recorded(&self, node: &Node, known_hosts: &Path) {
        self.record(Asked::Recorded(node.to_string(), known_hosts.to_path_buf()));
    }
}
