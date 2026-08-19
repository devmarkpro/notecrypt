#![cfg(unix)]

use std::ffi::OsString;
use std::path::Path;
use std::time::{Duration, Instant};

use notecrypt_platform_fs::{SupervisedProcess, SupervisedProcessState};

fn poll_until(
    process: &mut SupervisedProcess,
    expected: fn(SupervisedProcessState) -> bool,
) -> SupervisedProcessState {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let state = process.poll(true).unwrap();
        if expected(state) {
            return state;
        }
        assert!(
            Instant::now() < deadline,
            "supervised process did not settle"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn normal_owned_process_exit_is_observed_and_reaped_with_anchor_intact() {
    let mut process = SupervisedProcess::spawn(
        Path::new("/usr/bin/true").as_os_str(),
        &[],
        Path::new("/tmp/notecrypt-supervision-probe"),
        true,
    )
    .unwrap();

    let state = poll_until(&mut process, |state| {
        matches!(state, SupervisedProcessState::Exited(_))
    });

    assert_eq!(state, SupervisedProcessState::Exited(Some(0)));
}

#[test]
fn stop_requested_after_leader_exit_does_not_turn_zombie_anchor_into_failure() {
    let mut process = SupervisedProcess::spawn(
        Path::new("/usr/bin/true").as_os_str(),
        &[],
        Path::new("/tmp/notecrypt-supervision-probe"),
        true,
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !process.leader_exited_unreaped().unwrap() {
        assert!(
            Instant::now() < deadline,
            "leader did not publish exit state"
        );
        std::thread::yield_now();
    }

    process.request_stop().unwrap();
    let state = poll_until(&mut process, |state| {
        matches!(state, SupervisedProcessState::Exited(_))
    });

    assert_eq!(state, SupervisedProcessState::Exited(Some(0)));
}

#[test]
fn leader_exit_with_a_live_group_child_is_not_false_terminal() {
    let arguments = vec![OsString::from("-c"), OsString::from("sleep 30 &")];
    let mut process = SupervisedProcess::spawn(
        Path::new("/bin/sh").as_os_str(),
        &arguments,
        Path::new("/tmp/notecrypt-supervision-probe"),
        true,
    )
    .unwrap();

    poll_until(&mut process, |state| {
        state == SupervisedProcessState::LeaderExitedTreeActive
    });
    process.force_stop().unwrap();
    poll_until(&mut process, |state| {
        matches!(state, SupervisedProcessState::Exited(_))
    });
}

#[cfg(all(feature = "test-support", target_vendor = "apple"))]
#[test]
fn apple_process_group_batch_fails_closed_when_its_callback_budget_expires() {
    use notecrypt_platform_fs::process_groups_have_other_members;
    use notecrypt_platform_fs::workspace_test_support::inject_process_group_probe_budget;

    let group = rustix::process::getpid().as_raw_nonzero().get();
    inject_process_group_probe_budget(0);
    let error = process_groups_have_other_members(&[group], &mut [false])
        .expect_err("the injected callback budget must fail closed");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(process_groups_have_other_members(&[group, group], &mut [false, false]).is_err());
}

#[cfg(all(feature = "test-support", target_os = "linux"))]
#[test]
fn linux_process_stat_parser_rejects_every_incomplete_identity() {
    use notecrypt_platform_fs::workspace_test_support::{
        parse_process_group_stat, process_group_stat_is_live,
    };

    assert_eq!(
        parse_process_group_stat(b"123 (name with ) delimiter) S 1 456 0", 123).unwrap(),
        456
    );
    assert!(process_group_stat_is_live(b"123 (name) S 1 456 0", 123).unwrap());
    assert!(!process_group_stat_is_live(b"123 (name) Z 1 456 0", 123).unwrap());
    assert_eq!(
        parse_process_group_stat(b"2 (kthreadd) S 0 0 0", 2).unwrap(),
        0
    );
    for malformed in [
        &b"124 (name) S 1 456 0"[..],
        &b"123 name S 1 456 0"[..],
        &b"123 (name)"[..],
        &b"123 (name) SS 1 456 0"[..],
        &b"123 (name) S parent 456 0"[..],
        &b"123 (name) S 1"[..],
        &b"123 (name) S 1 -1 0"[..],
        &b"123 (name) S 1 group 0"[..],
    ] {
        assert!(parse_process_group_stat(malformed, 123).is_err());
    }
}

#[cfg(all(feature = "test-support", target_os = "linux"))]
#[test]
fn linux_process_group_batch_rejects_invalid_input_and_scan_budget_exhaustion() {
    use notecrypt_platform_fs::process_groups_have_other_members;
    use notecrypt_platform_fs::workspace_test_support::{
        inject_process_group_scan_entry_budget, take_process_group_scan_count,
    };

    assert!(process_groups_have_other_members(&[1], &mut []).is_err());
    assert!(process_groups_have_other_members(&[0], &mut [false]).is_err());

    take_process_group_scan_count();
    inject_process_group_scan_entry_budget(0);
    let group = rustix::process::getpid().as_raw_nonzero().get();
    assert!(process_groups_have_other_members(&[group, group], &mut [false, false]).is_err());
    let error = process_groups_have_other_members(&[group, group + 1], &mut [false, false])
        .expect_err("the injected traversal budget must fail closed");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(take_process_group_scan_count(), 1);
}

#[cfg(all(feature = "test-support", target_os = "linux"))]
#[test]
fn linux_process_group_scan_budget_excludes_scheduler_delay() {
    use notecrypt_platform_fs::process_groups_have_other_members;
    use notecrypt_platform_fs::workspace_test_support::{
        inject_process_group_scan_wall_budget, inject_process_group_scan_wall_delay,
    };

    let group = rustix::process::getpid().as_raw_nonzero().get();
    inject_process_group_scan_wall_budget(Duration::from_secs(1));
    inject_process_group_scan_wall_delay(Duration::from_millis(150));
    process_groups_have_other_members(&[group], &mut [false])
        .expect("scheduler delay must not consume the bounded scan work budget");
}

#[cfg(all(feature = "test-support", target_os = "linux"))]
#[test]
fn linux_process_group_scan_wall_backstop_fails_closed() {
    use notecrypt_platform_fs::process_groups_have_other_members;
    use notecrypt_platform_fs::workspace_test_support::{
        inject_process_group_scan_wall_budget, inject_process_group_scan_wall_delay,
    };

    let group = rustix::process::getpid().as_raw_nonzero().get();
    inject_process_group_scan_wall_budget(Duration::from_millis(5));
    inject_process_group_scan_wall_delay(Duration::from_millis(10));
    let error = process_groups_have_other_members(&[group], &mut [false])
        .expect_err("the hard wall backstop must fail closed");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
}
