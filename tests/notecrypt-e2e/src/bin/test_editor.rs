use std::path::Path;
use std::process::{Command, ExitCode};
use std::time::Duration;

fn main() -> ExitCode {
    let arguments: Vec<_> = std::env::args_os().collect();
    let workspace = arguments.last().map(std::path::PathBuf::from);
    if arguments.iter().any(|argument| argument == "--descendant") {
        return wait_for_release(workspace.as_deref(), "descendant-ready");
    }
    if arguments.iter().any(|argument| argument == "--detached") {
        return wait_for_release(workspace.as_deref(), "detached-ready");
    }
    let executable = std::env::args_os().next().unwrap_or_default();
    let mode = Path::new(&executable)
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .unwrap_or("normal");
    match mode {
        "normal" => {
            mark(workspace.as_deref(), "ready");
            ExitCode::SUCCESS
        }
        "nonzero" => {
            mark(workspace.as_deref(), "ready");
            ExitCode::from(17)
        }
        "signal" => {
            mark(workspace.as_deref(), "ready");
            terminate_self_by_signal()
        }
        "argv" => {
            write_argv(workspace.as_deref(), &arguments);
            ExitCode::SUCCESS
        }
        "child" => spawn_child_that_outlives_leader(workspace.as_deref()),
        "blocking" => wait_for_release(workspace.as_deref(), "ready"),
        "unsaved-delay" => {
            let result = wait_for_release(workspace.as_deref(), "ready");
            mark(workspace.as_deref(), "saved");
            result
        }
        "ignore-termination" => {
            ignore_termination();
            wait_for_release(workspace.as_deref(), "ready")
        }
        "detach" => spawn_detached(workspace.as_deref()),
        _ => ExitCode::from(64),
    }
}

#[cfg(unix)]
fn terminate_self_by_signal() -> ExitCode {
    notecrypt_platform_fs::test_support::terminate_self_by_signal()
}

#[cfg(not(unix))]
fn terminate_self_by_signal() -> ExitCode {
    ExitCode::from(128)
}

fn marker(workspace: Option<&Path>, suffix: &str) -> std::path::PathBuf {
    workspace
        .expect("workspace argument")
        .with_extension(suffix)
}

fn mark(workspace: Option<&Path>, suffix: &str) {
    std::fs::write(marker(workspace, suffix), b"ready").expect("write test editor barrier");
}

#[cfg(unix)]
fn write_argv(workspace: Option<&Path>, arguments: &[std::ffi::OsString]) {
    use std::os::unix::ffi::OsStrExt as _;

    let mut encoded = Vec::new();
    for argument in &arguments[1..arguments.len() - 1] {
        let bytes = argument.as_os_str().as_bytes();
        encoded.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_le_bytes());
        encoded.extend_from_slice(bytes);
    }
    std::fs::write(marker(workspace, "argv"), encoded).expect("write exact editor argv");
}

#[cfg(not(unix))]
fn write_argv(workspace: Option<&Path>, arguments: &[std::ffi::OsString]) {
    let rendered = arguments[1..arguments.len() - 1]
        .iter()
        .map(|argument| argument.to_string_lossy())
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(marker(workspace, "argv"), rendered).expect("write editor argv");
}

fn wait_for_marker(workspace: Option<&Path>, suffix: &str) {
    while !marker(workspace, suffix).exists() {
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn wait_for_release(workspace: Option<&Path>, ready: &str) -> ExitCode {
    let _held_plaintext = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(workspace.expect("workspace argument"))
        .expect("open plaintext workspace file");
    mark(workspace, ready);
    wait_for_marker(workspace, "release");
    ExitCode::SUCCESS
}

#[allow(clippy::zombie_processes)]
fn spawn_child_that_outlives_leader(workspace: Option<&Path>) -> ExitCode {
    let current = std::env::current_exe().expect("test editor executable");
    let mut command = Command::new(current);
    command
        .arg("--descendant")
        .arg(workspace.expect("workspace argument"));
    // The supervisor, rather than this exiting leader, must discover and reap the descendant.
    let _child = command.spawn().expect("test editor descendant");
    wait_for_marker(workspace, "descendant-ready");
    ExitCode::SUCCESS
}

#[cfg(unix)]
fn ignore_termination() {
    notecrypt_platform_fs::test_support::ignore_termination();
}

#[cfg(not(unix))]
fn ignore_termination() {}

#[cfg(unix)]
#[allow(clippy::zombie_processes)]
fn spawn_detached(workspace: Option<&Path>) -> ExitCode {
    let current = std::env::current_exe().expect("test editor executable");
    let mut command = Command::new(current);
    command
        .arg("--detached")
        .arg(workspace.expect("workspace argument"));
    notecrypt_platform_fs::test_support::configure_detached_child(&mut command);
    // The deliberate orphan proves unsupported containment fails closed before this mode launches.
    let _child = command.spawn().expect("detached test editor child");
    wait_for_marker(workspace, "detached-ready");
    ExitCode::SUCCESS
}

#[cfg(not(unix))]
fn spawn_detached(_workspace: Option<&Path>) -> ExitCode {
    ExitCode::from(70)
}
