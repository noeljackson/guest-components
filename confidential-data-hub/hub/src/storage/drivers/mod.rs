// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{
    fs::File,
    io::Write,
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Command, Output, Stdio},
};

use anyhow::{anyhow, bail, Context, Result};
use nix::libc;
use tempfile::NamedTempFile;
use tracing::debug;
use which::which;

pub mod filesystem;
pub mod luks2;
pub mod zfs;

/// Run a command and return the stdout and stderr.
pub fn run_command(
    command: &str,
    args: &[&str],
    inputs: Option<&[u8]>,
) -> Result<(String, String)> {
    let output = run_command_output(command, args, inputs)?;
    let stdout = String::from_utf8_lossy(&output.stdout).replace("\n", "\n\t");
    let stderr = String::from_utf8_lossy(&output.stderr).replace("\n", "\n\t");

    if !output.status.success() {
        bail!(
            "Failed to run command {command} with args: {args:#?}\nstdout: {stdout}\nstderr: {stderr}",
        );
    }

    debug!("command {command} with args: {args:#?} \n\t stdout: {stdout} \n\t stderr: {stderr}");

    Ok((stdout, stderr))
}

/// Run a command while preserving one already-open file descriptor across
/// `execve`.
///
/// Callers pass the file to the child as `/proc/self/fd/<n>`. Clearing
/// `FD_CLOEXEC` only in the post-fork child keeps the parent descriptor policy
/// unchanged and prevents the child from resolving an attacker-controlled
/// pathname again.
pub fn run_command_with_inherited_file(
    command: &str,
    args: &[&str],
    inputs: Option<&[u8]>,
    inherited_file: &File,
) -> Result<(String, String)> {
    let output = run_command_output_inner(command, args, inputs, Some(inherited_file))?;
    let stdout = String::from_utf8_lossy(&output.stdout).replace("\n", "\n\t");
    let stderr = String::from_utf8_lossy(&output.stderr).replace("\n", "\n\t");

    if !output.status.success() {
        bail!(
            "Failed to run command {command} with args: {args:#?}\nstdout: {stdout}\nstderr: {stderr}",
        );
    }

    debug!("command {command} with args: {args:#?} \n\t stdout: {stdout} \n\t stderr: {stderr}");

    Ok((stdout, stderr))
}

/// Run a command without interpreting its exit status.
///
/// Some probes use a nonzero exit code to report "not found". Returning the
/// untouched `Output` lets those callers distinguish that result from a failure
/// to start or communicate with the child.
pub fn run_command_output(command: &str, args: &[&str], inputs: Option<&[u8]>) -> Result<Output> {
    run_command_output_inner(command, args, inputs, None)
}

fn run_command_output_inner(
    command: &str,
    args: &[&str],
    inputs: Option<&[u8]>,
    inherited_file: Option<&File>,
) -> Result<Output> {
    let _ = which(command).with_context(|| format!("command `{command}` not found"))?;
    let mut child_command = Command::new(command);
    child_command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args(args);

    if let Some(inherited_file) = inherited_file {
        let inherited_fd = inherited_file.as_raw_fd();
        // SAFETY: the closure invokes only async-signal-safe `fcntl` calls in
        // the post-fork child. The descriptor is held by `inherited_file`
        // throughout `spawn`, and the parent descriptor flags are untouched.
        unsafe {
            child_command.pre_exec(move || {
                let flags = libc::fcntl(inherited_fd, libc::F_GETFD);
                if flags == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(inherited_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    let mut status = child_command.spawn()?;

    if let Some(inputs) = inputs {
        if let Some(mut stdin) = status.stdin.take() {
            stdin.write_all(inputs)?;
            stdin.flush()?;
        } else {
            bail!(
                "Failed to get stdin from the command thus failed to write inputs to the command"
            );
        }
    }

    Ok(status.wait_with_output()?)
}

/// A wrapper for the loop device backed by a temporary file.
pub struct TempFileLoopDevice {
    _file: NamedTempFile,
    loop_path: String,
}

impl TempFileLoopDevice {
    /// Create a new loop device.
    pub fn new(size_bytes: u64) -> Result<Self> {
        let file = NamedTempFile::new()?;
        file.as_file().set_len(size_bytes)?;

        let path = file
            .path()
            .to_str()
            .ok_or_else(|| anyhow!("failed to get path of the temporary file"))?;
        let (stdout, _) = run_command("losetup", &["--find", "--show", path], None)?;

        let loop_path = stdout.trim().to_string();

        Ok(Self {
            _file: file,
            loop_path,
        })
    }

    pub fn dev_path(&self) -> &str {
        &self.loop_path
    }
}

impl Drop for TempFileLoopDevice {
    fn drop(&mut self) {
        let _ = run_command("losetup", &["-d", self.loop_path.as_str()], None).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inherited_file_stays_bound_after_its_path_is_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("device");
        let old_path = directory.path().join("device.old");
        std::fs::write(&path, b"pinned-device").unwrap();
        let pinned = File::open(&path).unwrap();

        std::fs::rename(&path, &old_path).unwrap();
        std::fs::write(&path, b"replacement-device").unwrap();

        let inherited_path = format!("/proc/self/fd/{}", pinned.as_raw_fd());
        let (pinned_output, _) =
            run_command_with_inherited_file("cat", &[&inherited_path], None, &pinned).unwrap();
        let (replacement_output, _) = run_command("cat", &[path.to_str().unwrap()], None).unwrap();

        assert_eq!(pinned_output, "pinned-device");
        assert_eq!(replacement_output, "replacement-device");
    }
}
