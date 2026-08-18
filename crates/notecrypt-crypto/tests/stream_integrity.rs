use std::sync::atomic::{AtomicBool, Ordering};

use notecrypt_crypto::{
    AeadEnvelopeParts, ChunkFingerprintContext, ChunkKeyEnvelope, ChunkKeyPlaintext,
    ChunkKeyWrapContext, ContentChunkContext, ContentChunkEnvelope, ContentChunkPlaintext,
    CryptoError, PublicEnvelopeIdentity, SecureRandom, TypedAeadEnvelope, VaultRootKey,
    decrypt_content_chunk, derive_vault_keys, encrypt_content_chunk, fingerprint_chunk,
    unwrap_chunk_key, verify_chunk_fingerprint, wrap_chunk_key,
};

const MIB: usize = 1_048_576;

struct CountingRandom {
    calls: usize,
    next: u8,
}

impl CountingRandom {
    fn new(next: u8) -> Self {
        Self { calls: 0, next }
    }
}

impl SecureRandom for CountingRandom {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
        self.calls += 1;
        destination.fill(self.next);
        self.next = self.next.wrapping_add(1);
        Ok(())
    }
}

struct PartialFailure;

impl SecureRandom for PartialFailure {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
        let partial = destination.len() / 2;
        destination[..partial].fill(0xa5);
        Err(CryptoError::RandomSource)
    }
}

fn error_of<T>(result: Result<T, CryptoError>) -> CryptoError {
    match result {
        Ok(_) => panic!("expected a cryptographic error"),
        Err(error) => error,
    }
}

fn identity(kind: u8, vault: u8, object: u8) -> PublicEnvelopeIdentity {
    PublicEnvelopeIdentity {
        profile_id: 1,
        vault_id: [vault; 16],
        object_kind: kind,
        format_version: 1,
        object_id: [object; 32],
    }
}

fn content_context(vault: u8, object: u8) -> ContentChunkContext {
    ContentChunkContext::try_new(identity(ContentChunkContext::OBJECT_KIND, vault, object)).unwrap()
}

fn wrap_context(vault: u8, object: u8) -> ChunkKeyWrapContext {
    ChunkKeyWrapContext::try_new(identity(ChunkKeyWrapContext::OBJECT_KIND, vault, object)).unwrap()
}

fn root_and_keys() -> notecrypt_crypto::VaultKeys {
    root_and_keys_with_seed(1)
}

fn root_and_keys_with_seed(seed: u8) -> notecrypt_crypto::VaultKeys {
    let mut random = CountingRandom::new(seed);
    let root = VaultRootKey::generate(&mut random).unwrap();
    derive_vault_keys(&root).unwrap()
}

fn protected_semantics(file: u8, sequence: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16 + 8);
    bytes.extend_from_slice(&[file; 16]);
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes
}

fn round_trip(size: usize) {
    let keys = root_and_keys();
    let plaintext = vec![0x5a; size];
    let mut random = CountingRandom::new(10);
    let chunk_key = ChunkKeyPlaintext::generate(&mut random).unwrap();
    let content_context = content_context(2, 3);
    let wrap_context = wrap_context(2, 4);
    let content = encrypt_content_chunk(
        &content_context,
        ContentChunkPlaintext::try_new(plaintext).unwrap(),
        &chunk_key,
        &mut random,
    )
    .unwrap();
    let wrapped = wrap_chunk_key(
        &wrap_context,
        chunk_key,
        &keys.content_wrapping,
        &mut random,
    )
    .unwrap();

    assert_ne!(content.parts().nonce(), wrapped.parts().nonce());
    let recovered_key = unwrap_chunk_key(&wrap_context, &wrapped, &keys.content_wrapping).unwrap();
    decrypt_content_chunk(&content_context, &content, &recovered_key)
        .unwrap()
        .into_protected_bytes()
        .consume(|recovered| {
            assert_eq!(recovered.len(), size);
            assert!(recovered.iter().all(|byte| *byte == 0x5a));
        });
}

#[test]
fn every_candidate_boundary_round_trips_or_rejects_above_profile_limit() {
    for size in [
        0,
        1,
        MIB - 1,
        MIB,
        MIB + 1,
        2 * MIB - 1,
        2 * MIB,
        2 * MIB + 1,
        4 * MIB - 1,
        4 * MIB,
    ] {
        round_trip(size);
    }
    assert_eq!(
        error_of(ContentChunkPlaintext::try_new(vec![0; 4 * MIB + 1])),
        CryptoError::PlaintextTooLarge,
    );
}

#[test]
fn fingerprint_binds_protected_file_position_length_and_plaintext() {
    let keys = root_and_keys();
    let context = ChunkFingerprintContext::profile_one();
    let plaintext = b"private chunk";
    let semantics = protected_semantics(1, 7);
    let expected =
        fingerprint_chunk(&context, &semantics, plaintext, &keys.chunk_fingerprint).unwrap();

    verify_chunk_fingerprint(
        &context,
        &semantics,
        plaintext,
        &expected,
        &keys.chunk_fingerprint,
    )
    .unwrap();
    for changed in [protected_semantics(2, 7), protected_semantics(1, 8)] {
        assert_eq!(
            error_of(verify_chunk_fingerprint(
                &context,
                &changed,
                plaintext,
                &expected,
                &keys.chunk_fingerprint,
            )),
            CryptoError::Authentication,
        );
    }
    assert_eq!(
        error_of(verify_chunk_fingerprint(
            &context,
            &semantics,
            b"modified chunk with a different length",
            &expected,
            &keys.chunk_fingerprint,
        )),
        CryptoError::Authentication,
    );
}

#[test]
fn fingerprint_rejects_non_profile_semantics_and_unbounded_plaintext() {
    let keys = root_and_keys();
    let context = ChunkFingerprintContext::profile_one();
    for semantics in [vec![0; 23], vec![0; 25], vec![0; 4_097]] {
        assert_eq!(
            error_of(fingerprint_chunk(
                &context,
                &semantics,
                b"chunk",
                &keys.chunk_fingerprint,
            )),
            CryptoError::InvalidPlaintextLength,
        );
    }
    assert_eq!(
        error_of(fingerprint_chunk(
            &context,
            &protected_semantics(1, 0),
            &vec![0; 4 * MIB + 1],
            &keys.chunk_fingerprint,
        )),
        CryptoError::PlaintextTooLarge,
    );
}

#[test]
fn content_rejects_every_public_envelope_mutation() {
    let mut random = CountingRandom::new(20);
    let key = ChunkKeyPlaintext::generate(&mut random).unwrap();
    let context = content_context(1, 2);

    for mutation in 0..6 {
        let envelope = encrypt_content_chunk(
            &context,
            ContentChunkPlaintext::try_new(b"private".to_vec()).unwrap(),
            &key,
            &mut random,
        )
        .unwrap();
        let parts = envelope.into_parts();
        let mut changed_identity = *parts.identity();
        let mut nonce = *parts.nonce();
        let mut ciphertext = parts.ciphertext().to_vec();
        let mut tag = *parts.tag();
        match mutation {
            0 => changed_identity.vault_id[0] ^= 1,
            1 => changed_identity.object_id[0] ^= 1,
            2 => nonce[0] ^= 1,
            3 => ciphertext[0] ^= 1,
            4 => tag[0] ^= 1,
            5 => ciphertext.push(0),
            _ => unreachable!(),
        }
        let changed = ContentChunkEnvelope::try_from_parts(
            AeadEnvelopeParts::try_new(changed_identity, &nonce, ciphertext, &tag).unwrap(),
        )
        .unwrap();
        assert_eq!(
            error_of(decrypt_content_chunk(&context, &changed, &key)),
            CryptoError::Authentication,
        );
    }
}

#[test]
fn key_wrap_rejects_wrong_identity_and_modified_bytes() {
    let keys = root_and_keys();
    let context = wrap_context(1, 2);

    for mutation in 0..4 {
        let mut random = CountingRandom::new(30);
        let key = ChunkKeyPlaintext::generate(&mut random).unwrap();
        let wrapped = wrap_chunk_key(&context, key, &keys.content_wrapping, &mut random).unwrap();
        let parts = wrapped.into_parts();
        let mut changed_identity = *parts.identity();
        let mut nonce = *parts.nonce();
        let mut ciphertext = parts.ciphertext().to_vec();
        let mut tag = *parts.tag();
        match mutation {
            0 => changed_identity.object_id[0] ^= 1,
            1 => nonce[0] ^= 1,
            2 => ciphertext[0] ^= 1,
            3 => tag[0] ^= 1,
            _ => unreachable!(),
        }
        let changed = ChunkKeyEnvelope::try_from_parts(
            AeadEnvelopeParts::try_new(changed_identity, &nonce, ciphertext, &tag).unwrap(),
        )
        .unwrap();
        assert_eq!(
            error_of(unwrap_chunk_key(&context, &changed, &keys.content_wrapping,)),
            CryptoError::Authentication,
        );
    }
}

#[test]
fn every_chunk_primitive_rejects_a_substituted_key() {
    let keys = root_and_keys_with_seed(1);
    let wrong_keys = root_and_keys_with_seed(2);
    let mut random = CountingRandom::new(70);
    let content_key = ChunkKeyPlaintext::generate(&mut random).unwrap();
    let wrong_content_key = ChunkKeyPlaintext::generate(&mut random).unwrap();
    let content = encrypt_content_chunk(
        &content_context(1, 2),
        ContentChunkPlaintext::try_new(b"private".to_vec()).unwrap(),
        &content_key,
        &mut random,
    )
    .unwrap();
    assert_eq!(
        error_of(decrypt_content_chunk(
            &content_context(1, 2),
            &content,
            &wrong_content_key,
        )),
        CryptoError::Authentication,
    );

    let wrapped = wrap_chunk_key(
        &wrap_context(1, 3),
        content_key,
        &keys.content_wrapping,
        &mut random,
    )
    .unwrap();
    assert_eq!(
        error_of(unwrap_chunk_key(
            &wrap_context(1, 3),
            &wrapped,
            &wrong_keys.content_wrapping,
        )),
        CryptoError::Authentication,
    );

    let semantics = protected_semantics(1, 0);
    let fingerprint = fingerprint_chunk(
        &ChunkFingerprintContext::profile_one(),
        &semantics,
        b"private",
        &keys.chunk_fingerprint,
    )
    .unwrap();
    assert_eq!(
        error_of(verify_chunk_fingerprint(
            &ChunkFingerprintContext::profile_one(),
            &semantics,
            b"private",
            &fingerprint,
            &wrong_keys.chunk_fingerprint,
        )),
        CryptoError::Authentication,
    );
}

#[test]
fn partial_random_failure_returns_no_key_content_or_wrapped_envelope() {
    assert_eq!(
        error_of(ChunkKeyPlaintext::generate(&mut PartialFailure)),
        CryptoError::RandomSource,
    );

    let keys = root_and_keys();
    let mut key_random = CountingRandom::new(40);
    let key = ChunkKeyPlaintext::generate(&mut key_random).unwrap();
    assert_eq!(
        error_of(encrypt_content_chunk(
            &content_context(1, 2),
            ContentChunkPlaintext::try_new(b"private".to_vec()).unwrap(),
            &key,
            &mut PartialFailure,
        )),
        CryptoError::RandomSource,
    );

    assert_eq!(
        error_of(wrap_chunk_key(
            &wrap_context(1, 3),
            key,
            &keys.content_wrapping,
            &mut PartialFailure,
        )),
        CryptoError::RandomSource,
    );
}

fn atomic_new_chunk(
    random: &mut dyn SecureRandom,
) -> Result<(ContentChunkEnvelope, ChunkKeyEnvelope), CryptoError> {
    let keys = root_and_keys();
    let key = ChunkKeyPlaintext::generate(random)?;
    let content = encrypt_content_chunk(
        &content_context(1, 2),
        ContentChunkPlaintext::try_new(b"private".to_vec())?,
        &key,
        random,
    )?;
    let wrapped = wrap_chunk_key(&wrap_context(1, 3), key, &keys.content_wrapping, random)?;
    Ok((content, wrapped))
}

#[test]
fn wrap_failure_discards_the_preceding_content_result_atomically() {
    struct FailOnThirdFill(usize);
    impl SecureRandom for FailOnThirdFill {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
            self.0 += 1;
            let partial = destination.len() / 2;
            destination[..partial].fill(9);
            if self.0 == 3 {
                Err(CryptoError::RandomSource)
            } else {
                Ok(())
            }
        }
    }

    assert_eq!(
        error_of(atomic_new_chunk(&mut FailOnThirdFill(0))),
        CryptoError::RandomSource,
    );
}

fn exercise_bounded_store_loop(total_bytes: u64, cancel_after: Option<usize>) -> (usize, usize) {
    let keys = root_and_keys();
    let cancelled = AtomicBool::new(false);
    let mut random = CountingRandom::new(60);
    let mut completed = 0_usize;
    let mut remaining = total_bytes;
    let mut peak_live_chunk_bytes = 0_usize;

    while remaining > 0 {
        if cancelled.load(Ordering::Acquire) {
            break;
        }
        let size = usize::try_from(remaining.min(MIB as u64)).unwrap();
        let plaintext = vec![0x3c; size];
        peak_live_chunk_bytes = peak_live_chunk_bytes.max(plaintext.capacity());
        let key = ChunkKeyPlaintext::generate(&mut random).unwrap();
        let content = encrypt_content_chunk(
            &content_context(1, 2),
            ContentChunkPlaintext::try_new(plaintext).unwrap(),
            &key,
            &mut random,
        )
        .unwrap();
        peak_live_chunk_bytes = peak_live_chunk_bytes.max(content.parts().ciphertext().len());
        let wrapped = wrap_chunk_key(
            &wrap_context(1, 3),
            key,
            &keys.content_wrapping,
            &mut random,
        )
        .unwrap();
        let recovered_key =
            unwrap_chunk_key(&wrap_context(1, 3), &wrapped, &keys.content_wrapping).unwrap();
        let recovered =
            decrypt_content_chunk(&content_context(1, 2), &content, &recovered_key).unwrap();
        peak_live_chunk_bytes =
            peak_live_chunk_bytes.max(content.parts().ciphertext().len().saturating_add(size));
        recovered
            .into_protected_bytes()
            .consume(|recovered| assert_eq!(recovered.len(), size));

        completed += 1;
        remaining -= size as u64;
        if cancel_after == Some(completed) {
            cancelled.store(true, Ordering::Release);
        }
    }

    (completed, peak_live_chunk_bytes)
}

#[test]
fn sixty_four_mib_store_loop_processes_and_drops_one_bounded_chunk_at_a_time() {
    let (completed, peak_live_chunk_bytes) = exercise_bounded_store_loop(64 * MIB as u64, None);
    assert_eq!(completed, 64);
    assert_eq!(peak_live_chunk_bytes, 2 * MIB);
}

#[test]
fn cancellation_is_observed_between_bounded_chunk_calls() {
    let (completed, _) = exercise_bounded_store_loop(64 * MIB as u64, Some(3));
    assert_eq!(completed, 3);
}

#[test]
#[ignore = "runs on dedicated Task 21 performance workers"]
fn one_gib_stream_corpus_stays_bounded() {
    let (completed, peak) = exercise_bounded_store_loop(1_024 * MIB as u64, None);
    assert_eq!(completed, 1_024);
    assert!(peak <= 2 * MIB);
}

#[test]
#[ignore = "runs on dedicated Task 21 performance workers"]
fn ten_gib_stream_corpus_stays_bounded() {
    let (completed, peak) = exercise_bounded_store_loop(10 * 1_024 * MIB as u64, None);
    assert_eq!(completed, 10 * 1_024);
    assert!(peak <= 2 * MIB);
}
