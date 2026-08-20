use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::{Zeroize, Zeroizing};

use crate::recovery::validate_recovery_passphrase;
use crate::{CryptoError, RecoveryPassphrase, RecoveryWrappingKey};

pub const ARGON2_MEMORY_FLOOR_KIB: u32 = 65_536;
pub const ARGON2_MEMORY_CEILING_KIB: u32 = 1_048_576;
pub const ARGON2_ITERATIONS_FLOOR: u32 = 3;
pub const ARGON2_ITERATIONS_CEILING: u32 = 10;
pub const ARGON2_PARALLELISM_FLOOR: u32 = 1;
pub const ARGON2_PARALLELISM_CEILING: u32 = 16;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Argon2idParameters {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

pub struct ValidatedArgon2idParameters(Argon2idParameters);

impl ValidatedArgon2idParameters {
    #[must_use]
    pub const fn parameters(&self) -> Argon2idParameters {
        self.0
    }
}

impl TryFrom<Argon2idParameters> for ValidatedArgon2idParameters {
    type Error = CryptoError;

    fn try_from(value: Argon2idParameters) -> Result<Self, Self::Error> {
        if !(ARGON2_MEMORY_FLOOR_KIB..=ARGON2_MEMORY_CEILING_KIB).contains(&value.memory_kib)
            || !(ARGON2_ITERATIONS_FLOOR..=ARGON2_ITERATIONS_CEILING).contains(&value.iterations)
            || !(ARGON2_PARALLELISM_FLOOR..=ARGON2_PARALLELISM_CEILING).contains(&value.parallelism)
        {
            return Err(CryptoError::InvalidKdfParameters);
        }
        checked_memory_bytes(
            value.memory_kib,
            u64::try_from(usize::MAX).map_err(|_| CryptoError::InvalidKdfParameters)?,
        )?;
        Params::new(
            value.memory_kib,
            value.iterations,
            value.parallelism,
            Some(32),
        )
        .map_err(|_| CryptoError::InvalidKdfParameters)?;
        Ok(Self(value))
    }
}

pub fn derive_recovery_wrapping_key(
    passphrase: &RecoveryPassphrase,
    salt: &[u8; 16],
    parameters: ValidatedArgon2idParameters,
    cancel: &AtomicBool,
) -> Result<RecoveryWrappingKey, CryptoError> {
    validate_recovery_passphrase(passphrase)?;
    derive_with(parameters, cancel, |parameters, output| {
        run_argon2(
            parameters,
            passphrase.expose_secret().as_bytes(),
            salt,
            output,
            cancel,
        )
    })
}

fn derive_with(
    parameters: ValidatedArgon2idParameters,
    cancel: &AtomicBool,
    derive: impl FnOnce(Argon2idParameters, &mut [u8; 32]) -> Result<(), CryptoError>,
) -> Result<RecoveryWrappingKey, CryptoError> {
    if cancel.load(Ordering::Acquire) {
        return Err(CryptoError::Cancelled);
    }
    let mut output = Box::new([0_u8; 32]);
    if let Err(error) = derive(parameters.0, output.as_mut()) {
        output.zeroize();
        return Err(error);
    }
    if cancel.load(Ordering::Acquire) {
        output.zeroize();
        return Err(CryptoError::Cancelled);
    }
    Ok(RecoveryWrappingKey::from_boxed_bytes(output))
}

pub fn calibrate_argon2id(
    target: Duration,
    cancel: &AtomicBool,
) -> Result<ValidatedArgon2idParameters, CryptoError> {
    calibrate_with(target, cancel, |parameters| {
        let mut output = Zeroizing::new([0_u8; 32]);
        let started = Instant::now();
        run_argon2(
            parameters,
            b"notecrypt calibration input",
            &[0_u8; 16],
            &mut output,
            cancel,
        )?;
        Ok(started.elapsed())
    })
}

fn run_argon2(
    parameters: Argon2idParameters,
    passphrase: &[u8],
    salt: &[u8; 16],
    output: &mut [u8; 32],
    cancel: &AtomicBool,
) -> Result<(), CryptoError> {
    run_argon2_with_allocator(
        parameters,
        passphrase,
        salt,
        output,
        cancel,
        |block_count| {
            let mut memory = Vec::new();
            memory
                .try_reserve_exact(block_count)
                .map_err(|_| CryptoError::Allocation)?;
            memory.resize(block_count, Block::default());
            Ok(Zeroizing::new(memory))
        },
    )
}

fn run_argon2_with_allocator(
    parameters: Argon2idParameters,
    passphrase: &[u8],
    salt: &[u8; 16],
    output: &mut [u8; 32],
    cancel: &AtomicBool,
    allocate: impl FnOnce(usize) -> Result<Zeroizing<Vec<Block>>, CryptoError>,
) -> Result<(), CryptoError> {
    let params = Params::new(
        parameters.memory_kib,
        parameters.iterations,
        parameters.parallelism,
        Some(32),
    )
    .map_err(|_| CryptoError::InvalidKdfParameters)?;
    let block_count = params.block_count();
    let mut memory = allocate(block_count)?;
    if cancel.load(Ordering::Acquire) {
        return Err(CryptoError::Cancelled);
    }
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(passphrase, salt, output, memory.as_mut_slice())
        .map_err(|_| CryptoError::KeyDerivation)
}

fn checked_memory_bytes(memory_kib: u32, max_addressable: u64) -> Result<usize, CryptoError> {
    let byte_count = u64::from(memory_kib)
        .checked_mul(1_024)
        .ok_or(CryptoError::InvalidKdfParameters)?;
    if byte_count > max_addressable {
        return Err(CryptoError::InvalidKdfParameters);
    }
    usize::try_from(byte_count).map_err(|_| CryptoError::InvalidKdfParameters)
}

fn calibrate_with(
    target: Duration,
    cancel: &AtomicBool,
    mut sample: impl FnMut(Argon2idParameters) -> Result<Duration, CryptoError>,
) -> Result<ValidatedArgon2idParameters, CryptoError> {
    const MAX_MEMORY_CALIBRATION_SAMPLES: usize = 16;

    let minimum = Duration::from_millis(750);
    let maximum = Duration::from_millis(1_500);
    if !(minimum..=maximum).contains(&target) {
        return Err(CryptoError::InvalidKdfParameters);
    }
    let mut candidate = Argon2idParameters {
        memory_kib: ARGON2_MEMORY_FLOOR_KIB,
        iterations: ARGON2_ITERATIONS_FLOOR,
        parallelism: ARGON2_PARALLELISM_FLOOR,
    };

    for _ in 0..MAX_MEMORY_CALIBRATION_SAMPLES {
        let elapsed = measure_calibration_candidate(candidate, cancel, &mut sample)?;
        if (minimum..=maximum).contains(&elapsed) {
            return ValidatedArgon2idParameters::try_from(candidate);
        }
        if elapsed > maximum && candidate.memory_kib == ARGON2_MEMORY_FLOOR_KIB {
            return Err(CryptoError::CalibrationFailed);
        }
        if elapsed < minimum && candidate.memory_kib == ARGON2_MEMORY_CEILING_KIB {
            return calibrate_ceiling_iterations(cancel, &mut sample, minimum, maximum);
        }

        let scaled = u128::from(candidate.memory_kib)
            .saturating_mul(target.as_nanos())
            .saturating_div(elapsed.as_nanos().max(1));
        let bounded = scaled.clamp(
            u128::from(ARGON2_MEMORY_FLOOR_KIB),
            u128::from(ARGON2_MEMORY_CEILING_KIB),
        ) as u32;
        candidate.memory_kib = if bounded == candidate.memory_kib {
            if elapsed < minimum {
                candidate.memory_kib.saturating_add(1)
            } else {
                candidate.memory_kib.saturating_sub(1)
            }
        } else {
            bounded
        };
    }
    Err(CryptoError::CalibrationFailed)
}

fn calibrate_ceiling_iterations(
    cancel: &AtomicBool,
    sample: &mut impl FnMut(Argon2idParameters) -> Result<Duration, CryptoError>,
    minimum: Duration,
    maximum: Duration,
) -> Result<ValidatedArgon2idParameters, CryptoError> {
    for iterations in (ARGON2_ITERATIONS_FLOOR + 1)..=ARGON2_ITERATIONS_CEILING {
        let candidate = Argon2idParameters {
            memory_kib: ARGON2_MEMORY_CEILING_KIB,
            iterations,
            parallelism: ARGON2_PARALLELISM_FLOOR,
        };
        let elapsed = measure_calibration_candidate(candidate, cancel, sample)?;
        if (minimum..=maximum).contains(&elapsed) {
            return ValidatedArgon2idParameters::try_from(candidate);
        }
        if elapsed > maximum {
            return Err(CryptoError::CalibrationFailed);
        }
    }
    Err(CryptoError::CalibrationFailed)
}

fn measure_calibration_candidate(
    candidate: Argon2idParameters,
    cancel: &AtomicBool,
    sample: &mut impl FnMut(Argon2idParameters) -> Result<Duration, CryptoError>,
) -> Result<Duration, CryptoError> {
    if cancel.load(Ordering::Acquire) {
        return Err(CryptoError::Cancelled);
    }
    ValidatedArgon2idParameters::try_from(candidate)?;
    let elapsed = sample(candidate)?;
    if cancel.load(Ordering::Acquire) {
        return Err(CryptoError::Cancelled);
    }
    Ok(elapsed)
}

#[cfg(test)]
mod tests {
    use super::{
        Argon2idParameters, ValidatedArgon2idParameters, calibrate_with, checked_memory_bytes,
        derive_with, run_argon2_with_allocator,
    };
    use crate::CryptoError;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn cancellation_after_argon2_prevents_key_publication() {
        let cancel = AtomicBool::new(false);
        let parameters = ValidatedArgon2idParameters::try_from(Argon2idParameters {
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 1,
        })
        .unwrap();

        let result = derive_with(parameters, &cancel, |_, output| {
            output.fill(42);
            cancel.store(true, Ordering::Release);
            Ok(())
        });

        assert!(matches!(result, Err(CryptoError::Cancelled)));
    }

    #[test]
    fn calibration_measures_the_final_candidate_inside_the_profile_window() {
        let cancel = AtomicBool::new(false);
        let mut sampled = Vec::new();
        let result = calibrate_with(
            std::time::Duration::from_millis(1_000),
            &cancel,
            |parameters| {
                sampled.push(parameters);
                let millis = u64::from(parameters.memory_kib) * 1_000 / 131_072;
                Ok(std::time::Duration::from_millis(millis))
            },
        )
        .unwrap();

        assert!(sampled.len() >= 2);
        assert!(sampled.last() == Some(&result.parameters()));
        let final_millis = u64::from(result.parameters().memory_kib) * 1_000 / 131_072;
        assert!((750..=1_500).contains(&final_millis));
    }

    #[test]
    fn calibration_searches_iterations_after_memory_reaches_the_ceiling() {
        let mut sampled = Vec::new();
        let result = calibrate_with(
            std::time::Duration::from_millis(1_000),
            &AtomicBool::new(false),
            |parameters| {
                sampled.push(parameters);
                let elapsed = if parameters.memory_kib < 1_048_576 {
                    100
                } else if parameters.iterations == 3 {
                    700
                } else {
                    1_000
                };
                Ok(std::time::Duration::from_millis(elapsed))
            },
        )
        .unwrap();

        assert_eq!(result.parameters().memory_kib, 1_048_576);
        assert_eq!(result.parameters().iterations, 4);
        assert!(sampled.last() == Some(&result.parameters()));
        assert!(sampled.contains(&Argon2idParameters {
            memory_kib: 1_048_576,
            iterations: 3,
            parallelism: 1,
        }));
    }

    #[test]
    fn calibration_fails_after_measuring_every_permitted_ceiling_iteration() {
        let mut sampled = Vec::new();
        let result = calibrate_with(
            std::time::Duration::from_millis(1_000),
            &AtomicBool::new(false),
            |parameters| {
                sampled.push(parameters);
                Ok(std::time::Duration::from_millis(749))
            },
        );

        assert!(matches!(result, Err(CryptoError::CalibrationFailed)));
        for iterations in 3..=10 {
            assert!(sampled.contains(&Argon2idParameters {
                memory_kib: 1_048_576,
                iterations,
                parallelism: 1,
            }));
        }
        assert_eq!(sampled.last().map(|value| value.iterations), Some(10));
    }

    #[test]
    fn calibration_iteration_budget_is_independent_of_memory_search() {
        let mut sampled = Vec::new();
        let result = calibrate_with(
            std::time::Duration::from_millis(1_000),
            &AtomicBool::new(false),
            |parameters| {
                sampled.push(parameters);
                let elapsed = if parameters.memory_kib == 1_048_576 && parameters.iterations == 9 {
                    1_000
                } else {
                    749
                };
                Ok(std::time::Duration::from_millis(elapsed))
            },
        )
        .unwrap();

        assert_eq!(result.parameters().memory_kib, 1_048_576);
        assert_eq!(result.parameters().iterations, 9);
        assert!(sampled.last() == Some(&result.parameters()));
        for iterations in 3..=9 {
            assert!(sampled.contains(&Argon2idParameters {
                memory_kib: 1_048_576,
                iterations,
                parallelism: 1,
            }));
        }
    }

    #[test]
    fn calibration_fails_when_the_floor_is_already_too_slow() {
        let result = calibrate_with(
            std::time::Duration::from_millis(1_000),
            &AtomicBool::new(false),
            |_| Ok(std::time::Duration::from_millis(1_501)),
        );

        assert!(matches!(result, Err(CryptoError::CalibrationFailed)));
    }

    #[test]
    fn memory_byte_count_rejects_a_narrow_platform_overflow() {
        assert!(matches!(
            checked_memory_bytes(u32::MAX, u64::from(u32::MAX)),
            Err(CryptoError::InvalidKdfParameters),
        ));
    }

    #[test]
    fn cancellation_after_allocation_prevents_the_argon_call() {
        let cancel = AtomicBool::new(false);
        let parameters = Argon2idParameters {
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 1,
        };
        let mut output = [0_u8; 32];
        let result = run_argon2_with_allocator(
            parameters,
            b"alpha beta gamma delta epsilon",
            &[1; 16],
            &mut output,
            &cancel,
            |_| {
                cancel.store(true, Ordering::Release);
                Ok(zeroize::Zeroizing::new(Vec::new()))
            },
        );

        assert!(matches!(result, Err(CryptoError::Cancelled)));
        assert_eq!(output, [0; 32]);
    }
}
