use std::borrow::Cow;

use russh::keys::{Algorithm, EcdsaCurve, HashAlg};
use russh::{Preferred, cipher, kex, mac};

/// Host key algorithms offered by default, strongest first. `ssh-rsa` (SHA-1) is legacy.
const HOST_KEYS: &[Algorithm] = &[
    Algorithm::Ed25519,
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP384,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP521,
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha512),
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha256),
    },
];
/// Host key algorithms added for older servers.
const LEGACY_HOST_KEYS: &[Algorithm] = &[Algorithm::Rsa { hash: None }];
/// Key exchange methods added for older servers, all SHA-1 based.
const LEGACY_KEX: &[kex::Name] = &[kex::DH_G14_SHA1, kex::DH_GEX_SHA1, kex::DH_G1_SHA1];
/// Ciphers added for older servers.
const LEGACY_CIPHERS: &[cipher::Name] = &[
    cipher::AES_256_CBC,
    cipher::AES_192_CBC,
    cipher::AES_128_CBC,
];
/// MACs added for older servers.
const LEGACY_MACS: &[mac::Name] = &[mac::HMAC_SHA1_ETM, mac::HMAC_SHA1];

/// The algorithms to offer a server, most preferred first. With `legacy`, older SHA-1 and CBC
/// algorithms are added after the modern ones, so a server that supports both still
/// negotiates a modern one.
pub(crate) fn preferred(legacy: bool) -> Preferred {
    let mut preferred = Preferred {
        key: Cow::Borrowed(HOST_KEYS),
        ..Preferred::DEFAULT
    };
    if legacy {
        preferred.key.to_mut().extend_from_slice(LEGACY_HOST_KEYS);
        preferred.kex = Cow::Owned(with_legacy_kex(&preferred.kex));
        preferred.cipher.to_mut().extend_from_slice(LEGACY_CIPHERS);
        preferred.mac.to_mut().extend_from_slice(LEGACY_MACS);
    }
    preferred
}

/// `kex` with the legacy methods added after the real methods, ahead of the extension names
/// (`ext-info-c` and the like) that `russh` lists at the end.
fn with_legacy_kex(kex: &[kex::Name]) -> Vec<kex::Name> {
    let end = kex
        .iter()
        .position(|name| *name == kex::EXTENSION_SUPPORT_AS_CLIENT)
        .unwrap_or(kex.len());
    let mut names = kex[..end].to_vec();
    names.extend_from_slice(LEGACY_KEX);
    names.extend_from_slice(&kex[end..]);
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_leave_out_legacy_algorithms() {
        let preferred = preferred(false);
        assert!(!preferred.key.contains(&Algorithm::Rsa { hash: None }));
        assert!(preferred.key.contains(&Algorithm::Ed25519));
        for name in LEGACY_KEX {
            assert!(!preferred.kex.contains(name));
        }
        for name in LEGACY_CIPHERS {
            assert!(!preferred.cipher.contains(name));
        }
        for name in LEGACY_MACS {
            assert!(!preferred.mac.contains(name));
        }
    }

    #[test]
    fn legacy_algorithms_come_after_modern_ones() {
        let modern = preferred(false);
        let legacy = preferred(true);
        assert_eq!(legacy.key[..modern.key.len()], modern.key[..]);
        assert_eq!(legacy.key.last(), Some(&Algorithm::Rsa { hash: None }));
        assert_eq!(legacy.cipher[..modern.cipher.len()], modern.cipher[..]);
        assert_eq!(legacy.mac[..modern.mac.len()], modern.mac[..]);
        for name in LEGACY_KEX {
            assert!(legacy.kex.contains(name));
        }
        for name in LEGACY_CIPHERS {
            assert!(legacy.cipher.contains(name));
        }
        for name in LEGACY_MACS {
            assert!(legacy.mac.contains(name));
        }
    }

    #[test]
    fn legacy_key_exchange_is_offered_after_modern_methods() {
        let legacy = preferred(true);
        let position = |name: &kex::Name| legacy.kex.iter().position(|kex| kex == name);
        assert!(position(&kex::DH_G14_SHA256) < position(&kex::DH_G14_SHA1));
        assert!(position(&kex::CURVE25519) < position(&kex::DH_G1_SHA1));
    }
}
