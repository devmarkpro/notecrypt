#[cfg(feature = "test-support")]
mod profile_table {
    use std::ffi::{OsStr, OsString};

    use notecrypt_editor_workspace::classify_editor_for_test as resolve_editor;
    use notecrypt_service::{
        EditorCommand, EditorResolutionRequest, EditorSupervisionMode, HostPortError,
        MAX_EDITOR_ARGUMENT_BYTES, MAX_EDITOR_ARGUMENTS, MAX_EDITOR_COMMAND_BYTES,
    };

    fn command(executable: &str, arguments: &[&str]) -> EditorCommand {
        EditorCommand::try_new(
            OsString::from(executable),
            arguments.iter().map(OsString::from).collect(),
        )
        .unwrap()
    }

    fn args(command: &EditorCommand) -> Vec<&OsStr> {
        command
            .arguments()
            .iter()
            .map(OsString::as_os_str)
            .collect()
    }

    #[test]
    fn explicit_editor_precedes_visual_and_editor() {
        let explicit = command("/Applications/Visual Studio Code.app/bin/code", &[]);
        let request = EditorResolutionRequest::try_new(
            Some(explicit),
            Some(OsString::from("nvim")),
            Some(OsString::from("nano")),
            EditorSupervisionMode::Blocking,
        )
        .unwrap();

        let resolved = resolve_editor(request).unwrap();

        assert_eq!(
            resolved.executable(),
            OsStr::new("/Applications/Visual Studio Code.app/bin/code")
        );
        assert_eq!(args(&resolved), [OsStr::new("--wait")]);
    }

    #[test]
    fn visual_precedes_editor_and_environment_is_one_literal_executable() {
        let request = EditorResolutionRequest::try_new(
            None,
            Some(OsString::from("/opt/Editors/My Vim/bin/nvim")),
            Some(OsString::from("nano")),
            EditorSupervisionMode::Strict,
        )
        .unwrap();

        let resolved = resolve_editor(request).unwrap();

        assert_eq!(
            resolved.executable(),
            OsStr::new("/opt/Editors/My Vim/bin/nvim")
        );
        assert!(resolved.arguments().is_empty());
    }

    #[test]
    fn supported_profiles_apply_only_the_required_blocking_arguments() {
        let cases: &[(&str, &[&str])] = &[
            ("vi", &[]),
            ("vim", &[]),
            ("nvim", &[]),
            ("nano", &[]),
            ("emacsclient", &[]),
            ("code", &["--wait"]),
            ("zed", &["--wait"]),
            ("notepad", &[]),
            ("notepad++", &["-multiInst", "-nosession"]),
        ];

        for (executable, expected) in cases {
            let request = EditorResolutionRequest::try_new(
                Some(command(executable, &[])),
                None,
                None,
                EditorSupervisionMode::Blocking,
            )
            .unwrap();
            let resolved = resolve_editor(request).unwrap();
            assert_eq!(
                args(&resolved),
                expected.iter().map(OsStr::new).collect::<Vec<_>>(),
                "profile {executable}"
            );
        }
    }

    #[test]
    fn all_optional_arguments_are_rejected_until_each_profile_has_a_positive_safety_proof() {
        for (executable, argument) in [
            ("vim", "--remote"),
            ("vim", "--remote-wait-silent"),
            ("vim", "--servername"),
            ("vim", "-g"),
            ("nvim", "--server"),
            ("nvim", "--embed"),
            ("vim", "-c"),
            ("vim", "--cmd"),
            ("vim", "-S"),
            ("vim", "+call system('setsid true')"),
            ("emacsclient", "--eval"),
            ("code", "--reuse-window"),
            ("code", "--"),
            ("vi", "--"),
            ("emacsclient", "--no-wait"),
            ("emacsclient", "-n"),
            ("vim", "-c"),
            ("vim", "--cmd"),
            ("vim", "-S"),
            ("vim", "+call system('setsid true')"),
            ("emacsclient", "--eval"),
            ("code", "--reuse-window"),
            ("code", "--"),
        ] {
            let request = EditorResolutionRequest::try_new(
                Some(command(executable, &[argument])),
                None,
                None,
                EditorSupervisionMode::Strict,
            )
            .unwrap();
            assert_eq!(
                resolve_editor(request).err(),
                Some(HostPortError::DetachedEditor)
            );
        }

        for (executable, argument) in [
            ("vim", "--remote"),
            ("vim", "--remote-expr"),
            ("vim", "--servername"),
            ("vim", "-g"),
            ("nvim", "--server"),
            ("nvim", "--embed"),
        ] {
            let request = EditorResolutionRequest::try_new(
                Some(command(executable, &[argument])),
                None,
                None,
                EditorSupervisionMode::Blocking,
            )
            .unwrap();
            assert_eq!(
                resolve_editor(request).err(),
                Some(HostPortError::DetachedEditor),
                "blocking profile {executable} accepted {argument}"
            );
        }
    }

    #[test]
    fn strict_resolution_rejects_an_unknown_editor_profile() {
        let request = EditorResolutionRequest::try_new(
            Some(command("detaching-editor", &[])),
            None,
            None,
            EditorSupervisionMode::Strict,
        )
        .unwrap();

        assert_eq!(
            resolve_editor(request).err(),
            Some(HostPortError::DetachedEditor)
        );
    }

    #[test]
    fn blocking_resolution_rejects_unknown_explicit_and_environment_profiles() {
        let explicit = EditorResolutionRequest::try_new(
            Some(command("detaching-editor", &[])),
            None,
            None,
            EditorSupervisionMode::Blocking,
        )
        .unwrap();
        assert_eq!(
            resolve_editor(explicit).err(),
            Some(HostPortError::DetachedEditor)
        );

        for (visual, editor) in [
            (Some(OsString::from("detaching-visual")), None),
            (None, Some(OsString::from("detaching-editor"))),
        ] {
            let environment = EditorResolutionRequest::try_new(
                None,
                visual,
                editor,
                EditorSupervisionMode::Blocking,
            )
            .unwrap();
            assert_eq!(
                resolve_editor(environment).err(),
                Some(HostPortError::DetachedEditor)
            );
        }
    }

    #[test]
    fn resolution_errors_are_redacted() {
        let secret = "SECRET_EDITOR_VALUE";
        let request = EditorResolutionRequest::try_new(
            Some(command("unknown", &[secret])),
            None,
            None,
            EditorSupervisionMode::Strict,
        )
        .unwrap();

        let error = match resolve_editor(request) {
            Ok(_) => panic!("unknown strict editor must be rejected"),
            Err(error) => error,
        };
        let rendered = format!("{error:?}");
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains("unknown"));
    }

    #[test]
    fn strict_resolution_rejects_blocking_but_unowned_ipc_profiles() {
        for executable in ["emacsclient", "code", "zed"] {
            let request = EditorResolutionRequest::try_new(
                Some(command(executable, &[])),
                None,
                None,
                EditorSupervisionMode::Strict,
            )
            .unwrap();
            assert_eq!(
                resolve_editor(request).err(),
                Some(HostPortError::DetachedEditor),
                "profile {executable}"
            );
        }
    }

    #[test]
    fn no_configuration_uses_only_the_supported_platform_default() {
        let request =
            EditorResolutionRequest::try_new(None, None, None, EditorSupervisionMode::Blocking)
                .unwrap();
        let resolved = resolve_editor(request).unwrap();

        #[cfg(windows)]
        assert_eq!(resolved.executable(), OsStr::new("notepad"));
        #[cfg(not(windows))]
        assert_eq!(resolved.executable(), OsStr::new("vi"));
        assert!(resolved.arguments().is_empty());
    }

    #[test]
    fn malformed_and_oversized_editor_inputs_fail_at_the_bounded_dto_boundary() {
        assert_eq!(
            EditorResolutionRequest::try_new(
                None,
                Some(OsString::new()),
                None,
                EditorSupervisionMode::Blocking,
            )
            .err(),
            Some(HostPortError::InvalidInput)
        );

        let oversized = OsString::from("x".repeat(MAX_EDITOR_ARGUMENT_BYTES + 1));
        assert_eq!(
            EditorResolutionRequest::try_new(
                None,
                Some(oversized.clone()),
                None,
                EditorSupervisionMode::Blocking,
            )
            .err(),
            Some(HostPortError::CapacityExceeded)
        );
        assert_eq!(
            EditorCommand::try_new(oversized, Vec::new()).err(),
            Some(HostPortError::CapacityExceeded)
        );

        let arguments = (0..=MAX_EDITOR_ARGUMENTS)
            .map(|_| OsString::from("x"))
            .collect();
        assert_eq!(
            EditorCommand::try_new(OsString::from("vim"), arguments).err(),
            Some(HostPortError::CapacityExceeded)
        );

        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt as _;

            let nul = OsString::from_vec(b"vim\0remote".to_vec());
            assert_eq!(
                EditorResolutionRequest::try_new(
                    None,
                    Some(nul),
                    None,
                    EditorSupervisionMode::Blocking,
                )
                .err(),
                Some(HostPortError::InvalidInput)
            );
            let non_utf8 = OsString::from_vec(vec![0xff]);
            let request = EditorResolutionRequest::try_new(
                None,
                Some(non_utf8),
                None,
                EditorSupervisionMode::Blocking,
            )
            .unwrap();
            assert_eq!(
                resolve_editor(request).err(),
                Some(HostPortError::InvalidInput)
            );
        }
    }

    #[test]
    fn editor_dto_bounds_accept_exact_limits_and_reject_each_max_plus_one() {
        let exact_environment = OsString::from("v".repeat(MAX_EDITOR_ARGUMENT_BYTES));
        assert!(
            EditorResolutionRequest::try_new(
                None,
                Some(exact_environment.clone()),
                Some(exact_environment),
                EditorSupervisionMode::Blocking,
            )
            .is_ok()
        );
        let oversized_environment = OsString::from("v".repeat(MAX_EDITOR_ARGUMENT_BYTES + 1));
        assert_eq!(
            EditorResolutionRequest::try_new(
                None,
                Some(oversized_environment.clone()),
                None,
                EditorSupervisionMode::Blocking,
            )
            .err(),
            Some(HostPortError::CapacityExceeded)
        );
        assert_eq!(
            EditorResolutionRequest::try_new(
                None,
                None,
                Some(oversized_environment),
                EditorSupervisionMode::Blocking,
            )
            .err(),
            Some(HostPortError::CapacityExceeded)
        );

        let exact_arguments = (0..MAX_EDITOR_ARGUMENTS)
            .map(|_| OsString::from("x"))
            .collect();
        assert!(EditorCommand::try_new(OsString::from("vim"), exact_arguments).is_ok());
        let oversized_arguments = (0..=MAX_EDITOR_ARGUMENTS)
            .map(|_| OsString::from("x"))
            .collect();
        assert_eq!(
            EditorCommand::try_new(OsString::from("vim"), oversized_arguments).err(),
            Some(HostPortError::CapacityExceeded)
        );

        let exact_argument = OsString::from("x".repeat(MAX_EDITOR_ARGUMENT_BYTES));
        assert!(EditorCommand::try_new(OsString::from("v"), vec![exact_argument]).is_ok());
        let oversized_argument = OsString::from("x".repeat(MAX_EDITOR_ARGUMENT_BYTES + 1));
        assert_eq!(
            EditorCommand::try_new(OsString::from("v"), vec![oversized_argument]).err(),
            Some(HostPortError::CapacityExceeded)
        );

        let mut exact_aggregate = (0..7)
            .map(|_| OsString::from("x".repeat(MAX_EDITOR_ARGUMENT_BYTES - 1)))
            .collect::<Vec<_>>();
        exact_aggregate.push(OsString::from(
            "x".repeat(MAX_EDITOR_COMMAND_BYTES - 1 - (7 * MAX_EDITOR_ARGUMENT_BYTES) - 1),
        ));
        assert!(EditorCommand::try_new(OsString::from("v"), exact_aggregate).is_ok());

        let mut oversized_aggregate = (0..7)
            .map(|_| OsString::from("x".repeat(MAX_EDITOR_ARGUMENT_BYTES - 1)))
            .collect::<Vec<_>>();
        oversized_aggregate.push(OsString::from(
            "x".repeat(MAX_EDITOR_COMMAND_BYTES - 1 - (7 * MAX_EDITOR_ARGUMENT_BYTES)),
        ));
        assert_eq!(
            EditorCommand::try_new(OsString::from("v"), oversized_aggregate).err(),
            Some(HostPortError::CapacityExceeded)
        );
    }
}

#[cfg(unix)]
mod production_resolution {
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use notecrypt_editor_workspace::resolve_editor;
    use notecrypt_service::{
        EditorCommand, EditorResolutionRequest, EditorSupervisionMode, HostPortError,
    };

    #[test]
    fn protected_platform_default_is_attested_before_resolution_succeeds() {
        let request =
            EditorResolutionRequest::try_new(None, None, None, EditorSupervisionMode::Blocking)
                .unwrap();

        let command = resolve_editor(request).unwrap();

        let expected = ["/usr/bin/vi", "/bin/vi"]
            .into_iter()
            .map(std::path::PathBuf::from)
            .find(|candidate| candidate.exists())
            .and_then(|candidate| fs::canonicalize(candidate).ok())
            .expect("the supported Unix default editor must be installed");
        assert_eq!(command.executable(), expected.as_os_str());
        assert!(command.arguments().is_empty());

        let repeated = EditorCommand::try_new(
            command.executable().to_os_string(),
            command.arguments().to_vec(),
        )
        .unwrap();
        let repeated = EditorResolutionRequest::try_new(
            Some(repeated),
            None,
            None,
            EditorSupervisionMode::Blocking,
        )
        .unwrap();
        let repeated = resolve_editor(repeated).unwrap();
        assert_eq!(repeated.executable(), command.executable());
        assert_eq!(repeated.arguments(), command.arguments());
    }

    #[test]
    fn user_owned_supported_basename_is_rejected_and_redacted() {
        let root = tempfile::tempdir().unwrap();
        let executable = root.path().join("vim");
        fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let command =
            EditorCommand::try_new(executable.clone().into_os_string(), Vec::new()).unwrap();
        let request = EditorResolutionRequest::try_new(
            Some(command),
            Some(OsString::from("vi")),
            None,
            EditorSupervisionMode::Blocking,
        )
        .unwrap();

        let error = match resolve_editor(request) {
            Ok(_) => panic!("user-owned executable must not be attested"),
            Err(error) => error,
        };

        assert_eq!(error, HostPortError::Permission);
        assert!(!format!("{error:?}").contains(executable.to_string_lossy().as_ref()));
    }
}
