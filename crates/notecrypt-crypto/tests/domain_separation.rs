use notecrypt_crypto::{
    AeadEnvelopeParts, CryptoError, MetadataContext, MetadataEnvelope, MetadataPlaintext,
    PublicEnvelopeIdentity, SecureRandom, TypedAeadEnvelope, VaultRootKey, decrypt_metadata,
    derive_vault_keys, encrypt_metadata,
};

struct FixedRandom([u8; 24]);

impl SecureRandom for FixedRandom {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
        destination.copy_from_slice(&self.0);
        Ok(())
    }
}

struct RootRandom;

impl SecureRandom for RootRandom {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
        for (index, byte) in destination.iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap();
        }
        Ok(())
    }
}

fn identity(vault_byte: u8, object_byte: u8) -> PublicEnvelopeIdentity {
    PublicEnvelopeIdentity {
        profile_id: 1,
        vault_id: [vault_byte; 16],
        object_kind: MetadataContext::OBJECT_KIND,
        format_version: 1,
        object_id: [object_byte; 32],
    }
}

#[test]
fn changing_any_available_identity_field_rejects_decryption() {
    let keys = derive_vault_keys(&VaultRootKey::generate(&mut RootRandom).unwrap()).unwrap();
    let context = MetadataContext::try_new(identity(1, 2)).unwrap();
    let envelope = encrypt_metadata(
        &context,
        MetadataPlaintext::try_new(b"private note".to_vec()).unwrap(),
        &keys.metadata,
        &mut FixedRandom([3; 24]),
    )
    .unwrap();

    for changed in [identity(9, 2), identity(1, 9)] {
        let changed_context = MetadataContext::try_new(changed).unwrap();
        assert!(matches!(
            decrypt_metadata(&changed_context, &envelope, &keys.metadata),
            Err(CryptoError::Authentication),
        ));
    }
}

#[test]
fn nonce_ciphertext_tag_and_length_mutations_reject_decryption() {
    let keys = derive_vault_keys(&VaultRootKey::generate(&mut RootRandom).unwrap()).unwrap();
    let context = MetadataContext::try_new(identity(1, 2)).unwrap();

    for mutation in 0..4 {
        let envelope = encrypt_metadata(
            &context,
            MetadataPlaintext::try_new(b"private note".to_vec()).unwrap(),
            &keys.metadata,
            &mut FixedRandom([3; 24]),
        )
        .unwrap();
        let parts = envelope.into_parts();
        let mut nonce = *parts.nonce();
        let mut ciphertext = parts.ciphertext().to_vec();
        let mut tag = *parts.tag();
        match mutation {
            0 => nonce[0] ^= 1,
            1 => ciphertext[0] ^= 1,
            2 => tag[0] ^= 1,
            3 => ciphertext.push(0),
            _ => unreachable!(),
        }
        let changed = MetadataEnvelope::try_from_parts(
            AeadEnvelopeParts::try_new(*parts.identity(), &nonce, ciphertext, &tag).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            decrypt_metadata(&context, &changed, &keys.metadata),
            Err(CryptoError::Authentication),
        ));
    }
}

#[test]
fn partial_nonce_failure_returns_no_envelope() {
    struct PartialFailure;
    impl SecureRandom for PartialFailure {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
            destination[..12].fill(9);
            Err(CryptoError::RandomSource)
        }
    }

    let keys = derive_vault_keys(&VaultRootKey::generate(&mut RootRandom).unwrap()).unwrap();
    let result = encrypt_metadata(
        &MetadataContext::try_new(identity(1, 2)).unwrap(),
        MetadataPlaintext::try_new(b"private note".to_vec()).unwrap(),
        &keys.metadata,
        &mut PartialFailure,
    );
    assert!(matches!(result, Err(CryptoError::RandomSource)));
}
