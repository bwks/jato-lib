use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A password, passphrase or private key.
///
/// The value is overwritten with zeros when the `Secret` is dropped, and `Debug` prints
/// `Secret(<redacted>)`. There is no `Display`, `Clone` or serialization, so a secret is not
/// copied or printed by accident.
///
/// Wiping covers only the memory the `Secret` owns. Copies made before it was created, such
/// as an earlier `String` that grew and was reallocated, are outside its reach.
pub struct Secret(String);

impl Secret {
    /// Wrap `value`, taking ownership so no other copy is left behind by Jato.
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// The secret value. Do not log it or keep a copy.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for Secret {}

#[cfg(test)]
mod tests {
    use super::*;

    const VALUE: &str = "hunter2-fixture";

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn debug_never_shows_the_value() {
        let secret = Secret::new(VALUE.into());
        assert_eq!(format!("{secret:?}"), "Secret(<redacted>)");
        assert!(!format!("{secret:#?}").contains(VALUE));
    }

    #[test]
    fn expose_returns_the_value() {
        assert_eq!(Secret::new(VALUE.into()).expose(), VALUE);
    }

    #[test]
    fn secret_is_wiped_on_drop() {
        assert_zeroize_on_drop::<Secret>();
    }
}
