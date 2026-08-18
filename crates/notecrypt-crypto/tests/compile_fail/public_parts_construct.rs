use notecrypt_crypto::{PublicAeadEnvelopeParts, PublicEnvelopeIdentity};

fn main() {
    let _ = PublicAeadEnvelopeParts {
        identity: PublicEnvelopeIdentity {
            profile_id: 1,
            vault_id: [0; 16],
            object_kind: 1,
            format_version: 1,
            object_id: [0; 32],
        },
        nonce: [0; 24],
        ciphertext: vec![0; 32],
        tag: [0; 16],
    };
}
