//! Keeping a person's answers for later connections, so a program that opens many
//! connections through the same server asks once.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::shared::node::Node;
use crate::shared::secret::Secret;
use crate::ssh::auth::Prompter;

/// Passphrases and passwords given so far, by question, shared by the prompters it makes.
///
/// Make a prompter with [`PromptCache::prompter`] for each connection attempt. It answers a
/// question from the cache the first time the connection asks it, and otherwise asks the
/// inner prompter, keeping the answer. A question asked again within one connection means
/// the last answer was wrong, so that one goes to the inner prompter. Declined questions are
/// not kept. Host key questions are never cached: each goes to the inner prompter.
///
/// One question is asked at a time across every prompter from the cache, so connections made
/// at once take turns at the terminal, and a connection that waited for another's answer to
/// the same question takes that answer instead of asking again.
///
/// Answers stay in memory, zeroized when the cache and every prompter from it are dropped.
#[derive(Clone, Debug, Default)]
pub struct PromptCache {
    answers: Arc<Mutex<HashMap<String, Secret>>>,
    /// Held while a question is answered, from the cache or by the inner prompter.
    asking: Arc<Mutex<()>>,
}

/// The prompter for one connection attempt: cached answers first, then `inner`.
#[derive(Debug)]
struct CachedPrompter {
    answers: Arc<Mutex<HashMap<String, Secret>>>,
    asking: Arc<Mutex<()>>,
    asked: Mutex<HashSet<String>>,
    inner: Arc<dyn Prompter>,
}

/// A question an answer is kept for.
enum Question<'a> {
    Passphrase(&'a Path),
    Password(&'a Node, &'a str),
}

impl PromptCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// A prompter for one connection attempt, answering from the cache and asking `inner`
    /// for the rest.
    pub fn prompter(&self, inner: Arc<dyn Prompter>) -> Arc<dyn Prompter> {
        Arc::new(CachedPrompter {
            answers: Arc::clone(&self.answers),
            asking: Arc::clone(&self.asking),
            asked: Mutex::new(HashSet::new()),
            inner,
        })
    }
}

impl CachedPrompter {
    fn answer(&self, question: &Question<'_>) -> Option<Secret> {
        let _turn = locked(&self.asking);
        let key = question.key();
        let first_time = locked(&self.asked).insert(key.clone());
        if first_time && let Some(cached) = locked(&self.answers).get(&key) {
            return Some(copy(cached));
        }
        let answer = match question {
            Question::Passphrase(path) => self.inner.passphrase(path),
            Question::Password(node, username) => self.inner.password(node, username),
        }?;
        locked(&self.answers).insert(key, copy(&answer));
        Some(answer)
    }
}

impl Prompter for CachedPrompter {
    fn passphrase(&self, path: &Path) -> Option<Secret> {
        self.answer(&Question::Passphrase(path))
    }

    fn password(&self, node: &Node, username: &str) -> Option<Secret> {
        self.answer(&Question::Password(node, username))
    }

    fn confirm_host_key(&self, node: &Node, fingerprint: &str) -> bool {
        let _turn = locked(&self.asking);
        self.inner.confirm_host_key(node, fingerprint)
    }

    fn host_key_recorded(&self, node: &Node, known_hosts: &Path) {
        let _turn = locked(&self.asking);
        self.inner.host_key_recorded(node, known_hosts);
    }
}

impl Question<'_> {
    /// What the answer is kept under.
    fn key(&self) -> String {
        match self {
            Question::Passphrase(path) => format!("passphrase {}", path.display()),
            Question::Password(node, username) => format!("password {username}@{node}"),
        }
    }
}

/// The lock's data; a thread that panicked holding it left nothing half-written.
fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn copy(secret: &Secret) -> Secret {
    Secret::new(secret.expose().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::thread;
    use std::time::Duration;

    /// Answers from a script and counts the questions.
    #[derive(Debug)]
    struct Scripted {
        answers: Mutex<VecDeque<Option<&'static str>>>,
        asked: Mutex<usize>,
        recorded: Mutex<usize>,
    }

    impl Scripted {
        fn new(answers: &[Option<&'static str>]) -> Arc<Self> {
            Arc::new(Self {
                answers: Mutex::new(answers.iter().copied().collect()),
                asked: Mutex::new(0),
                recorded: Mutex::new(0),
            })
        }

        fn asked(&self) -> usize {
            *self.asked.lock().unwrap()
        }

        fn next(&self) -> Option<Secret> {
            *self.asked.lock().unwrap() += 1;
            let answer = self.answers.lock().unwrap().pop_front().flatten()?;
            Some(Secret::new(answer.to_string()))
        }
    }

    impl Prompter for Scripted {
        fn passphrase(&self, _path: &Path) -> Option<Secret> {
            self.next()
        }

        fn password(&self, _node: &Node, _username: &str) -> Option<Secret> {
            self.next()
        }

        fn confirm_host_key(&self, _node: &Node, _fingerprint: &str) -> bool {
            self.next().is_some()
        }

        fn host_key_recorded(&self, _node: &Node, _known_hosts: &Path) {
            *self.recorded.lock().unwrap() += 1;
        }
    }

    fn key() -> &'static Path {
        Path::new("/home/me/.ssh/id_ed25519")
    }

    fn server() -> Node {
        Node::new("10.100.58.10", 22)
    }

    #[test]
    fn a_later_connection_reuses_the_answer() {
        let inner = Scripted::new(&[Some("pass")]);
        let cache = PromptCache::new();
        let first = cache.prompter(inner.clone());
        assert_eq!(first.passphrase(key()).unwrap().expose(), "pass");
        let second = cache.prompter(inner.clone());
        assert_eq!(second.passphrase(key()).unwrap().expose(), "pass");
        assert_eq!(inner.asked(), 1);
    }

    #[test]
    fn asked_again_in_one_connection_means_the_answer_was_wrong() {
        let inner = Scripted::new(&[Some("wrong"), Some("right")]);
        let cache = PromptCache::new();
        let first = cache.prompter(inner.clone());
        assert_eq!(first.passphrase(key()).unwrap().expose(), "wrong");
        assert_eq!(first.passphrase(key()).unwrap().expose(), "right");
        let second = cache.prompter(inner.clone());
        assert_eq!(second.passphrase(key()).unwrap().expose(), "right");
        assert_eq!(inner.asked(), 2);
    }

    #[test]
    fn a_declined_question_is_asked_again_next_time() {
        let inner = Scripted::new(&[None, Some("pw")]);
        let cache = PromptCache::new();
        assert!(
            cache
                .prompter(inner.clone())
                .password(&server(), "me")
                .is_none()
        );
        let answer = cache
            .prompter(inner.clone())
            .password(&server(), "me")
            .unwrap();
        assert_eq!(answer.expose(), "pw");
        assert_eq!(inner.asked(), 2);
    }

    #[test]
    fn passphrases_and_passwords_are_kept_apart() {
        let inner = Scripted::new(&[Some("pass"), Some("pw")]);
        let cache = PromptCache::new();
        let prompter = cache.prompter(inner.clone());
        assert_eq!(prompter.passphrase(key()).unwrap().expose(), "pass");
        assert_eq!(prompter.password(&server(), "me").unwrap().expose(), "pw");
    }

    #[test]
    fn host_key_questions_always_reach_the_inner_prompter() {
        let inner = Scripted::new(&[Some("yes"), None]);
        let cache = PromptCache::new();
        assert!(
            cache
                .prompter(inner.clone())
                .confirm_host_key(&server(), "SHA256:abc")
        );
        let second = cache.prompter(inner.clone());
        assert!(!second.confirm_host_key(&server(), "SHA256:abc"));
        second.host_key_recorded(&server(), Path::new("/home/me/.ssh/known_hosts"));
        assert_eq!(inner.asked(), 2);
        assert_eq!(*inner.recorded.lock().unwrap(), 1);
    }

    /// Answers every question after a pause, counting the questions and how many were
    /// being asked at once.
    #[derive(Debug, Default)]
    struct Slow {
        asked: Mutex<usize>,
        asking: Mutex<usize>,
        most_at_once: Mutex<usize>,
    }

    impl Slow {
        fn ask(&self) -> Option<Secret> {
            *self.asked.lock().unwrap() += 1;
            {
                let mut asking = self.asking.lock().unwrap();
                *asking += 1;
                let mut most = self.most_at_once.lock().unwrap();
                *most = (*most).max(*asking);
            }
            thread::sleep(Duration::from_millis(50));
            *self.asking.lock().unwrap() -= 1;
            Some(Secret::new("pass".to_string()))
        }
    }

    impl Prompter for Slow {
        fn passphrase(&self, _path: &Path) -> Option<Secret> {
            self.ask()
        }

        fn password(&self, _node: &Node, _username: &str) -> Option<Secret> {
            self.ask()
        }

        fn confirm_host_key(&self, _node: &Node, _fingerprint: &str) -> bool {
            self.ask().is_some()
        }

        fn host_key_recorded(&self, _node: &Node, _known_hosts: &Path) {}
    }

    #[test]
    fn connections_asking_at_once_are_asked_once() {
        let inner = Arc::new(Slow::default());
        let cache = PromptCache::new();
        let mut threads = Vec::new();
        for _ in 0..4 {
            let prompter = cache.prompter(inner.clone());
            threads.push(thread::spawn(move || prompter.passphrase(key())));
        }
        for thread in threads {
            assert_eq!(thread.join().unwrap().unwrap().expose(), "pass");
        }
        assert_eq!(*inner.asked.lock().unwrap(), 1);
    }

    #[test]
    fn one_question_is_asked_at_a_time() {
        let inner = Arc::new(Slow::default());
        let cache = PromptCache::new();
        let mut threads = Vec::new();
        for index in 0..4 {
            let prompter = cache.prompter(inner.clone());
            threads.push(thread::spawn(move || match index % 2 {
                0 => prompter.confirm_host_key(&server(), "SHA256:abc"),
                _ => prompter
                    .password(&Node::new("10.0.0.1", 22), "me")
                    .is_some(),
            }));
        }
        for thread in threads {
            assert!(thread.join().unwrap());
        }
        assert_eq!(*inner.most_at_once.lock().unwrap(), 1);
    }
}
