use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
#[cfg(unix)]
use std::path::PathBuf;

use notecrypt_platform_fs::TrustedExecutable;

#[cfg(unix)]
fn protected_platform_editor() -> PathBuf {
    ["/usr/bin/vi", "/bin/vi"]
        .into_iter()
        .map(PathBuf::from)
        .find(|candidate| candidate.exists())
        .expect("the supported Unix default editor must be installed")
}

#[test]
#[cfg(unix)]
fn production_attestation_accepts_the_protected_platform_editor() {
    let editor = fs::canonicalize(protected_platform_editor()).unwrap();

    let trusted = TrustedExecutable::open(&editor).unwrap();

    assert!(trusted.matches_named(&editor).unwrap());
}

#[test]
#[cfg(unix)]
fn production_attestation_rejects_a_user_owned_supported_basename() {
    let root = tempfile::tempdir().unwrap();
    let editor = root.path().join("vim");
    fs::copy(std::env::current_exe().unwrap(), &editor).unwrap();
    fs::set_permissions(&editor, fs::Permissions::from_mode(0o700)).unwrap();

    let error = match TrustedExecutable::open(&editor) {
        Ok(_) => panic!("user-owned executable must not be trusted"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
}

#[cfg(windows)]
#[test]
fn production_attestation_accepts_the_protected_windows_notepad() {
    let editor =
        notecrypt_platform_fs::windows_system_editor_candidate(std::ffi::OsStr::new("notepad"))
            .unwrap();

    let trusted = TrustedExecutable::open(&editor).unwrap_or_else(|error| {
        #[cfg(feature = "test-support")]
        panic!(
            "protected Notepad attestation failed: error={error}, acl_diagnostic={:?}",
            notecrypt_platform_fs::trusted_executable_test_support::take_acl_diagnostic()
        );
        #[cfg(not(feature = "test-support"))]
        panic!("protected Notepad attestation failed: error={error}");
    });

    assert!(trusted.matches_named(&editor).unwrap());
}

#[cfg(windows)]
#[test]
fn installed_notepad_plus_plus_is_attested_only_from_protected_program_files() {
    let editor =
        notecrypt_platform_fs::windows_system_editor_candidate(std::ffi::OsStr::new("notepad++"))
            .unwrap();
    if !editor.exists() {
        eprintln!("Notepad++ is not installed under the approved Program Files root");
        return;
    }

    let trusted = TrustedExecutable::open(&editor).unwrap();

    assert!(trusted.matches_named(&editor).unwrap());
}

#[cfg(windows)]
#[test]
fn production_attestation_rejects_a_user_owned_windows_notepad_copy() {
    let root = tempfile::tempdir().unwrap();
    let editor = root.path().join("notepad.exe");
    fs::copy(std::env::current_exe().unwrap(), &editor).unwrap();

    let error = match TrustedExecutable::open(&editor) {
        Ok(_) => panic!("user-owned executable must not be trusted"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
}

#[cfg(windows)]
#[test]
fn production_attestation_rejects_a_reparse_alias_to_system_notepad() {
    use std::os::windows::fs::symlink_file;

    let root = tempfile::tempdir().unwrap();
    let alias = root.path().join("notepad.exe");
    let editor =
        notecrypt_platform_fs::windows_system_editor_candidate(std::ffi::OsStr::new("notepad"))
            .unwrap();
    symlink_file(editor, &alias).expect("Windows runner must permit reparse-point EZE setup");

    let error = match TrustedExecutable::open(&alias) {
        Ok(_) => panic!("reparse alias must not gain production executable trust"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
}

#[cfg(feature = "test-support")]
#[test]
fn test_capability_is_bound_to_the_exact_retained_executable_identity() {
    let root = tempfile::tempdir().unwrap();
    let editor = root.path().join("vim");
    let replaced = root.path().join("replaced-vim");
    copy_executable(std::env::current_exe().unwrap().as_path(), &editor);
    let trusted = TrustedExecutable::open_test_only(&editor).unwrap();

    assert!(trusted.matches_named(&editor).unwrap());
    assert!(
        trusted
            .try_clone_if_matches_named(&editor)
            .unwrap()
            .is_some()
    );

    fs::rename(&editor, &replaced).unwrap();
    copy_executable(std::env::current_exe().unwrap().as_path(), &editor);

    assert!(!trusted.matches_named(&editor).unwrap());
    assert!(
        trusted
            .try_clone_if_matches_named(&editor)
            .unwrap()
            .is_none()
    );
}

#[cfg(all(windows, feature = "test-support"))]
#[test]
fn inherit_only_grants_do_not_control_the_current_trusted_object() {
    use notecrypt_platform_fs::trusted_executable_test_support::{
        TestAclPrincipal, file_write_data_access, generic_all_access,
        object_container_inherit_only_flags, verify_allowed_ace_for_current_object,
        verify_unsupported_ace_fails_closed,
    };

    verify_allowed_ace_for_current_object(
        TestAclPrincipal::CreatorOwner,
        object_container_inherit_only_flags(),
        generic_all_access(),
        true,
    )
    .expect("an inherit-only Creator Owner template must not control the current directory");

    for (principal, mask) in [
        (TestAclPrincipal::CreatorOwner, generic_all_access()),
        (TestAclPrincipal::Users, file_write_data_access()),
    ] {
        let error = verify_allowed_ace_for_current_object(principal, 0, mask, true)
            .expect_err("an effective unapproved write grant must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    verify_allowed_ace_for_current_object(TestAclPrincipal::System, 0, generic_all_access(), true)
        .expect("an effective SYSTEM write grant remains trusted");

    const SYSTEM_AUDIT_ACE_TYPE: u8 = 2;
    let unsupported = verify_unsupported_ace_fails_closed(
        SYSTEM_AUDIT_ACE_TYPE,
        u8::try_from(object_container_inherit_only_flags()).unwrap(),
    )
    .expect_err("inherit-only must not bypass unsupported ACE rejection");
    assert_eq!(unsupported.kind(), std::io::ErrorKind::PermissionDenied);
}

#[cfg(feature = "test-support")]
fn copy_executable(source: &std::path::Path, destination: &std::path::Path) {
    fs::copy(source, destination).unwrap();
    #[cfg(unix)]
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700)).unwrap();
}
