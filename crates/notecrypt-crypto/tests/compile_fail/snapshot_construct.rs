use notecrypt_crypto::{AeadEnvelopeParts, SnapshotEnvelope};

fn construct(encrypted: AeadEnvelopeParts) {
    let _ = SnapshotEnvelope {
        encrypted,
        outer_authenticator: [0; 32],
    };
}

fn main() {}
