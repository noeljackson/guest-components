// Copyright (c) 2024 Intel
// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! # LUKS2
//!
//! This module uses the `cryptsetup` binary to encrypt/decrypt a block device with LUKS2.
//!
//! It requires the `cryptsetup` CLI to be installed (e.g. `cryptsetup-bin` on Debian/Ubuntu).
//! No libcryptsetup-rs is linked, so the hub binary can be built as fully static.

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
    process::{Command, Stdio},
};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as b64, Engine};
use const_format::concatcp;
use nix::mount::{mount, MsFlags};
use serde::{Deserialize, Serialize};
use tokio::fs::symlink;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::hub::CDH_BASE_DIR;
use crate::storage::drivers::filesystem::{FsFormatter, FsType};
use crate::storage::drivers::run_command;
use crate::storage::volume_type::blockdevice::SourceType;

/// Algorithm of the integrity hash (dm-integrity format name)
const HMAC_SHA256: &str = "hmac-sha256";

const SECTOR_SIZE: u32 = 4096;

const CRYPTSETUP_BIN: &str = "cryptsetup";

const AUTO_INITIALIZATION_PROBE_BYTES: usize = 4 * 1024 * 1024;
const EXT4_SUPERBLOCK_MAGIC_OFFSET: u64 = 1024 + 56;
const EXT4_SUPERBLOCK_MAGIC: [u8; 2] = [0x53, 0xef];

pub const LUKS_HEADERS_STORAGE_DIR: &str = concatcp!(CDH_BASE_DIR, "/luks-headers");
pub const LUKS_HEADER_FILE_SUFFIX: &str = ".header";
pub const LUKS2_HEADER_MIN_SIZE_BYTES: u64 = 16 * 1024 * 1024;

/// Returns the path where the detached LUKS header for the given device is stored.
pub fn luks_header_path(device_path: &str) -> String {
    let name = b64.encode(device_path.as_bytes());
    format!(
        "{}/{}{}",
        LUKS_HEADERS_STORAGE_DIR, name, LUKS_HEADER_FILE_SUFFIX
    )
}

/// Creates and sizes the LUKS header file at `header_path`.
pub fn prepare_luks_header_file(header_path: &str) -> std::io::Result<()> {
    if let Some(parent) = Path::new(header_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(header_path)?;
    file.set_len(LUKS2_HEADER_MIN_SIZE_BYTES)?;
    Ok(())
}

/// The type of the target mount point.
#[derive(Serialize, Deserialize, PartialEq, Debug, Eq)]
#[serde(tag = "targetType")]
#[serde(rename_all = "camelCase")]
pub enum TargetType {
    /// The target is a device.
    Device,

    /// The target is a filesystem directory.
    FileSystem {
        /// The type of the target filesystem.
        /// In some cases, the filesystem type is determined by the higher
        /// level encryption_type ([`BlockDeviceEncryptType`]), so this
        /// field will be optional.
        #[serde(rename = "filesystemType")]
        #[serde(default)]
        filesystem_type: FsType,

        /// Extra options passed verbatim to mkfs.<fs> when it is needed.
        ///
        /// For LUKS2 + dm-integrity + ext4 on an empty device, CDH adds
        /// integrity-compatible ext4 defaults when the caller has not provided
        /// an explicit setting. In particular, CDH defaults lazy_itable_init to
        /// 0 to avoid lazy inode table writes against no-wipe dm-integrity
        /// devices.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[serde(rename = "mkfsOpts")]
        mkfs_opts: Option<String>,
    },
}

#[derive(Default)]
pub struct Luks2Formatter {
    pub integrity: bool,
}

impl Luks2Formatter {
    pub fn with_integrity(mut self, integrity: bool) -> Self {
        self.integrity = integrity;
        self
    }

    /// Encrypt (format) a block device as LUKS2 using the `cryptsetup` binary.
    pub fn encrypt_device(
        &self,
        device_path: &str,
        header_path: Option<&str>,
        passphrase: Zeroizing<Vec<u8>>,
    ) -> anyhow::Result<()> {
        let sector_size_str = SECTOR_SIZE.to_string();

        let mut args: Vec<&str> = vec![
            "--batch-mode",
            "luksFormat",
            "--type",
            "luks2",
            "--cipher",
            "aes-xts-plain64",
            "--sector-size",
            &sector_size_str,
        ];

        if let Some(h) = header_path {
            args.push("--header");
            args.push(h);
        }

        if self.integrity {
            args.push("--integrity");
            args.push(HMAC_SHA256);
            args.push("--integrity-no-wipe");
            args.push("--integrity-no-journal");
        }

        args.push(device_path);
        args.push("-"); // read passphrase from stdin

        run_cryptsetup_stdin(&args, &passphrase).context("cryptsetup luksFormat failed")?;
        Ok(())
    }

    /// Open a LUKS2 device using the `cryptsetup` binary.
    pub fn open_device(
        &self,
        device_path: &str,
        header_path: Option<&str>,
        name: &str,
        passphrase: Zeroizing<Vec<u8>>,
    ) -> anyhow::Result<()> {
        let mut args: Vec<&str> = vec!["luksOpen", "-d", "-", device_path, name];

        if let Some(h) = header_path {
            args.insert(1, h);
            args.insert(1, "--header");
        }

        run_cryptsetup_stdin(&args, &passphrase).context("cryptsetup luksOpen failed")?;
        debug!("device activated: {}", name);
        Ok(())
    }

    /// Close a LUKS2 mapping using the `cryptsetup` binary.
    pub fn close_device(&self, name: &str) -> anyhow::Result<()> {
        let args = ["luksClose", name];
        run_cryptsetup(&args).context("cryptsetup luksClose failed")?;
        Ok(())
    }

    /// Resolve a persistent direct-volume source without ever guessing that
    /// non-zero media is safe to initialize.
    pub fn resolve_auto_source(&self, device_path: &str) -> anyhow::Result<SourceType> {
        let probe_is_zeroed = initialization_probe_is_zeroed(device_path)?;
        let status = Command::new(CRYPTSETUP_BIN)
            .args(["isLuks", "--type", "luks2", device_path])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("failed to probe LUKS2 device")?;

        if status.success() {
            return Ok(SourceType::Encrypted);
        }

        if probe_is_zeroed {
            return Ok(SourceType::Empty);
        }

        bail!(
            "auto source refused: device is not valid LUKS2 and its initialization probe region is not completely zeroed"
        )
    }
}

fn initialization_probe_is_zeroed(device_path: &str) -> anyhow::Result<bool> {
    let mut device = File::open(device_path).context("failed to open auto source device")?;
    let mut probe = vec![0u8; AUTO_INITIALIZATION_PROBE_BYTES];
    device
        .read_exact(&mut probe)
        .context("auto source device is smaller than the initialization probe region")?;
    Ok(probe.iter().all(|byte| *byte == 0))
}

fn has_ext4_superblock(device_path: &str) -> anyhow::Result<bool> {
    let mut device = File::open(device_path).context("failed to open decrypted device")?;
    device
        .seek(SeekFrom::Start(EXT4_SUPERBLOCK_MAGIC_OFFSET))
        .context("failed to seek to ext4 superblock")?;
    let mut magic = [0u8; EXT4_SUPERBLOCK_MAGIC.len()];
    device
        .read_exact(&mut magic)
        .context("failed to read ext4 superblock")?;
    Ok(magic == EXT4_SUPERBLOCK_MAGIC)
}

/// Run cryptsetup with passphrase on stdin. Does not append newline.
fn run_cryptsetup_stdin(args: &[&str], passphrase: &[u8]) -> anyhow::Result<()> {
    let inputs = Zeroizing::new(passphrase.to_vec());
    let _ = run_command(CRYPTSETUP_BIN, args, Some(inputs))
        .context("failed to run cryptsetup with stdin")?;
    Ok(())
}

/// Run cryptsetup without stdin (e.g. luksClose).
fn run_cryptsetup(args: &[&str]) -> anyhow::Result<()> {
    let _ = run_command(CRYPTSETUP_BIN, args, None).context("failed to run cryptsetup")?;
    Ok(())
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Luks2MountParameters {
    /// Indicates whether to enable dm-integrity.
    ///
    /// When this is true and CDH formats an empty ext4 filesystem, CDH uses
    /// integrity-compatible formatting and applies ext4 safety defaults such as
    /// lazy_itable_init=0 unless the caller explicitly provides that option in
    /// mkfsOpts.
    #[serde(rename = "dataIntegrity")]
    #[serde(default)]
    pub data_integrity: Option<String>,

    /// Optional name for /dev/mapper/<name>
    #[serde(rename = "mapperName")]
    pub mapper_name: Option<String>,

    /// Grow the mounted ext4 filesystem to the current device size. The value
    /// is represented as a string because secure-mount options are a string
    /// map at the CDH boundary.
    #[serde(default)]
    pub grow: Option<String>,

    /// The type of the target mount point.
    /// Either `device` or `fileSystem`.
    #[serde(rename = "targetType")]
    #[serde(flatten)]
    pub target_type: TargetType,
}

pub struct Luks2MountOutcome {
    pub header_path: Option<String>,
    pub mapper_name: String,
}

fn parse_grow(value: Option<&str>) -> anyhow::Result<bool> {
    match value {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(_) => bail!("grow must be `true` or `false`"),
    }
}

impl Luks2MountParameters {
    /// Do the mount operation for the LUKS2 device.
    /// Returns the header path if the source type is empty.
    pub async fn do_mount(
        self,
        device_path: &str,
        mount_point: &str,
        key: Zeroizing<Vec<u8>>,
        source_type: SourceType,
    ) -> Result<Luks2MountOutcome> {
        let data_integrity = self.data_integrity.map(|s| s == "true").unwrap_or(false);
        let grow = parse_grow(self.grow.as_deref())?;
        let formatter = Luks2Formatter::default().with_integrity(data_integrity);
        let auto = source_type == SourceType::Auto;

        if auto && self.target_type == TargetType::Device {
            bail!("sourceType=auto requires an ext4 filesystem target");
        }

        let resolved_source = if auto {
            formatter.resolve_auto_source(device_path)?
        } else {
            source_type
        };

        // Preserve the legacy detached-header behavior for explicit `empty`.
        // Persistent `auto` volumes always use an on-device LUKS2 header so the
        // volume can be reopened by a replacement guest.
        let header_path = match (source_type, resolved_source) {
            (SourceType::Empty, _) => {
                warn!("encrypting an explicitly empty device");
                let header_path = luks_header_path(device_path);
                prepare_luks_header_file(&header_path)?;
                formatter
                    .encrypt_device(device_path, Some(&header_path), key.clone())
                    .context("Failed to encrypt LUKS2 device")?;
                Some(header_path)
            }
            (SourceType::Auto, SourceType::Empty) => {
                info!("initializing a zero-probed device as LUKS2");
                formatter
                    .encrypt_device(device_path, None, key.clone())
                    .context("Failed to initialize LUKS2 device")?;
                None
            }
            _ => None,
        };

        let devmapper_name = self.mapper_name.unwrap_or_else(|| {
            debug!("No mapper name provided, generating a random one");
            uuid::Uuid::new_v4().to_string()
        });

        debug!(device_path = device_path, "luks2 opening device");
        formatter
            .open_device(device_path, header_path.as_deref(), &devmapper_name, key)
            .context("Failed to open LUKS2 device")?;

        let dev_path = format!("/dev/mapper/{}", devmapper_name);
        let mut mounted = false;
        let mut symlink_created = false;
        let setup_result: Result<()> = async {
            match (self.target_type, resolved_source) {
                // 3.2 if the target type is device, do the symlink operation to map
                // the device path to the mount point.
                (TargetType::Device, _) => {
                    info!(
                        "symlinking device: {} to mount point: {}",
                        dev_path, mount_point
                    );
                    symlink(&dev_path, mount_point).await.with_context(|| {
                        format!(
                            "Failed to create symlink from {} to {}",
                            dev_path, mount_point
                        )
                    })?;
                    symlink_created = true;
                    debug!(mount_point = mount_point, "created symlink");
                }
                // 3.3 an encrypted source already has a filesystem.
                (
                    TargetType::FileSystem {
                        filesystem_type, ..
                    },
                    SourceType::Encrypted,
                ) => {
                    if auto && !has_ext4_superblock(&dev_path)? {
                        bail!("auto source refused: decrypted filesystem is not ext4");
                    }
                    info!(
                        "mounting device: {} to mount point: {}",
                        dev_path, mount_point
                    );
                    mount::<_, _, str, _>(
                        Some(&dev_path[..]),
                        mount_point,
                        Some(filesystem_type.as_ref()),
                        MsFlags::MS_NOATIME,
                        Some(""),
                    )
                    .with_context(|| {
                        format!(
                            "Failed to mount device {} to mount point {}",
                            dev_path, mount_point
                        )
                    })?;
                    mounted = true;

                    if grow {
                        FsFormatter {
                            fs_type: filesystem_type,
                            force: false,
                            args: Vec::new(),
                        }
                        .grow_online(&dev_path)
                        .context("Failed to grow mounted ext4 filesystem")?;
                    }
                    debug!(mount_point = mount_point, "mounted device");
                }
                // 3.4 an empty source must be formatted before it is mounted.
                (
                    TargetType::FileSystem {
                        filesystem_type,
                        mkfs_opts,
                    },
                    SourceType::Empty,
                ) => {
                    info!(
                        "formatting device: {} and mounting it to mount point: {}",
                        dev_path, mount_point
                    );
                    let args = mkfs_opts
                        .map(|s| {
                            s.split_ascii_whitespace()
                                .map(|x| x.to_string())
                                .collect::<Vec<String>>()
                        })
                        .unwrap_or_default();
                    debug!(
                        device_path = dev_path,
                        filesystem_type = ?filesystem_type,
                        args = ?args,
                        "formatting device"
                    );
                    let fs_formatter = FsFormatter {
                        fs_type: filesystem_type,
                        force: true,
                        args,
                    };

                    let format_result = if data_integrity {
                        fs_formatter.format_integrity_compatible(&dev_path)
                    } else {
                        fs_formatter.format(&dev_path)
                    };
                    format_result.with_context(|| {
                        format!(
                            "Failed to make filesystem {:?} of device {}",
                            filesystem_type, dev_path
                        )
                    })?;
                    if auto && !has_ext4_superblock(&dev_path)? {
                        bail!("initialized filesystem is not ext4");
                    }

                    debug!(device_path = dev_path, "mounting device");
                    mount(
                        Some(&dev_path[..]),
                        mount_point,
                        Some(filesystem_type.as_ref()),
                        MsFlags::MS_NOATIME,
                        Some(""),
                    )
                    .with_context(|| {
                        format!(
                            "Failed to mount device {} to mount point {}",
                            dev_path, mount_point
                        )
                    })?;
                    mounted = true;
                    if grow {
                        fs_formatter
                            .grow_online(&dev_path)
                            .context("Failed to grow mounted ext4 filesystem")?;
                    }
                    debug!(mount_point = mount_point, "mounted device");
                }
                (_, SourceType::Auto) => unreachable!("auto source must be resolved before setup"),
            }
            Ok(())
        }
        .await;

        if let Err(source) = setup_result {
            if mounted {
                let _ = nix::mount::umount(mount_point);
            }
            if symlink_created {
                let _ = tokio::fs::remove_file(mount_point).await;
            }
            if let Err(close_error) = formatter.close_device(&devmapper_name) {
                warn!(error = %close_error, "failed to close LUKS2 mapping after setup error");
            }
            return Err(source);
        }

        Ok(Luks2MountOutcome {
            header_path,
            mapper_name: devmapper_name,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom, Write};

    use serial_test::serial;
    use zeroize::Zeroizing;

    use crate::storage::volume_type::blockdevice::SourceType;

    use super::{
        initialization_probe_is_zeroed, luks_header_path, prepare_luks_header_file,
        run_cryptsetup_stdin, Luks2Formatter, AUTO_INITIALIZATION_PROBE_BYTES,
    };

    const TEST_PASSPHRASE: &[u8] = b"test";
    const NAME: &str = "test";

    #[test]
    fn auto_probe_accepts_only_a_complete_zeroed_region() {
        let mut zeroed = tempfile::NamedTempFile::new().unwrap();
        zeroed
            .as_file_mut()
            .set_len(AUTO_INITIALIZATION_PROBE_BYTES as u64)
            .unwrap();
        assert!(initialization_probe_is_zeroed(zeroed.path().to_str().unwrap()).unwrap());

        zeroed.as_file_mut().seek(SeekFrom::Start(4096)).unwrap();
        zeroed.as_file_mut().write_all(&[1]).unwrap();
        assert!(!initialization_probe_is_zeroed(zeroed.path().to_str().unwrap()).unwrap());

        let too_small = tempfile::NamedTempFile::new().unwrap();
        too_small.as_file().set_len(4096).unwrap();
        assert!(initialization_probe_is_zeroed(too_small.path().to_str().unwrap()).is_err());
    }

    #[test]
    fn auto_source_resolves_zeroed_and_refuses_unknown_media() {
        let mut device = tempfile::NamedTempFile::new().unwrap();
        device
            .as_file_mut()
            .set_len(AUTO_INITIALIZATION_PROBE_BYTES as u64)
            .unwrap();
        let formatter = Luks2Formatter::default();
        assert_eq!(
            formatter
                .resolve_auto_source(device.path().to_str().unwrap())
                .unwrap(),
            SourceType::Empty
        );

        device.as_file_mut().seek(SeekFrom::Start(0)).unwrap();
        device.as_file_mut().write_all(b"unknown-media").unwrap();
        assert!(formatter
            .resolve_auto_source(device.path().to_str().unwrap())
            .is_err());
    }

    #[test]
    fn cryptsetup_errors_never_include_the_passphrase() {
        let canary = b"codewire-secret-canary-never-log";
        let err = run_cryptsetup_stdin(
            &["luksOpen", "-d", "-", "/definitely/missing", "missing"],
            canary,
        )
        .unwrap_err();
        assert!(!format!("{err:#}").contains(std::str::from_utf8(canary).unwrap()));
    }

    /// Removes the LUKS header file on drop so tests don't leave files behind on panic.
    struct RemoveHeaderOnDrop(String);
    impl Drop for RemoveHeaderOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// Closes the dm-crypt device on drop so tests don't leave mapper devices behind.
    struct CloseDeviceOnDrop(String);
    impl Drop for CloseDeviceOnDrop {
        fn drop(&mut self) {
            let _ = Luks2Formatter::default().close_device(&self.0);
        }
    }

    #[test]
    #[cfg_attr(target_arch = "s390x", ignore)]
    #[serial]
    fn encrypt_open_device_no_integrity() {
        let mut bin_file = tempfile::NamedTempFile::new().unwrap();

        bin_file
            .as_file_mut()
            .write_all(&vec![0; 20 * 1024 * 1024])
            .unwrap();
        let path = bin_file.path().to_str().unwrap();

        let passphrase = Zeroizing::new(TEST_PASSPHRASE.to_vec());
        let luks2_formatter = Luks2Formatter { integrity: false };
        luks2_formatter
            .encrypt_device(path, None, passphrase.clone())
            .unwrap();

        luks2_formatter
            .open_device(path, None, NAME, passphrase)
            .unwrap();
        let _device_guard = CloseDeviceOnDrop(NAME.to_string());
    }

    #[test]
    #[cfg_attr(target_arch = "s390x", ignore)]
    #[serial]
    fn encrypt_open_device_integrity() {
        let mut bin_file = tempfile::NamedTempFile::new().unwrap();

        bin_file
            .as_file_mut()
            .write_all(&vec![0; 20 * 1024 * 1024])
            .unwrap();
        let path = bin_file.path().to_str().unwrap();

        let passphrase = Zeroizing::new(TEST_PASSPHRASE.to_vec());
        let luks2_formatter = Luks2Formatter { integrity: true };
        luks2_formatter
            .encrypt_device(path, None, passphrase.clone())
            .unwrap();

        luks2_formatter
            .open_device(path, None, NAME, passphrase)
            .unwrap();
        let _device_guard = CloseDeviceOnDrop(NAME.to_string());
    }

    #[test]
    #[cfg_attr(target_arch = "s390x", ignore)]
    #[serial]
    fn encrypt_open_device_no_integrity_with_header() {
        let mut bin_file = tempfile::NamedTempFile::new().unwrap();
        bin_file
            .as_file_mut()
            .write_all(&vec![0; 20 * 1024 * 1024])
            .unwrap();
        let path = bin_file.path().to_str().unwrap();
        let header_path = luks_header_path(path);
        prepare_luks_header_file(&header_path).unwrap();
        let _guard = RemoveHeaderOnDrop(header_path.clone());

        let passphrase = Zeroizing::new(TEST_PASSPHRASE.to_vec());
        let luks2_formatter = Luks2Formatter { integrity: false };
        luks2_formatter
            .encrypt_device(path, Some(&header_path), passphrase.clone())
            .unwrap();

        luks2_formatter
            .open_device(path, Some(&header_path), NAME, passphrase)
            .unwrap();
        let _device_guard = CloseDeviceOnDrop(NAME.to_string());
    }

    #[test]
    #[cfg_attr(target_arch = "s390x", ignore)]
    #[serial]
    fn encrypt_open_device_integrity_with_header() {
        let mut bin_file = tempfile::NamedTempFile::new().unwrap();
        bin_file
            .as_file_mut()
            .write_all(&vec![0; 20 * 1024 * 1024])
            .unwrap();
        let path = bin_file.path().to_str().unwrap();
        let header_path = luks_header_path(path);
        prepare_luks_header_file(&header_path).unwrap();
        let _guard = RemoveHeaderOnDrop(header_path.clone());

        let passphrase = Zeroizing::new(TEST_PASSPHRASE.to_vec());
        let luks2_formatter = Luks2Formatter { integrity: true };
        luks2_formatter
            .encrypt_device(path, Some(&header_path), passphrase.clone())
            .unwrap();

        luks2_formatter
            .open_device(path, Some(&header_path), NAME, passphrase)
            .unwrap();
        let _device_guard = CloseDeviceOnDrop(NAME.to_string());
    }

    #[test]
    #[serial]
    fn encrypt_with_existing_header_file() {
        let mut bin_file = tempfile::NamedTempFile::new().unwrap();
        bin_file
            .as_file_mut()
            .write_all(&vec![0; 20 * 1024 * 1024])
            .unwrap();
        let path = bin_file.path().to_str().unwrap();
        let header_path = luks_header_path(path);
        prepare_luks_header_file(&header_path).unwrap();
        let _guard = RemoveHeaderOnDrop(header_path.clone());

        let passphrase = Zeroizing::new(TEST_PASSPHRASE.to_vec());
        let luks2_formatter = Luks2Formatter { integrity: false };
        let result = luks2_formatter.encrypt_device(path, Some(&header_path), passphrase);
        assert!(result.is_ok());
    }

    #[test]
    #[serial]
    fn open_device_missing_header_file_fails() {
        let mut bin_file = tempfile::NamedTempFile::new().unwrap();
        bin_file
            .as_file_mut()
            .write_all(&vec![0; 20 * 1024 * 1024])
            .unwrap();
        let path = bin_file.path().to_str().unwrap();
        let header_path = luks_header_path(path);
        prepare_luks_header_file(&header_path).unwrap();
        let _guard = RemoveHeaderOnDrop(header_path.clone());

        let passphrase = Zeroizing::new(TEST_PASSPHRASE.to_vec());
        let luks2_formatter = Luks2Formatter { integrity: false };
        luks2_formatter
            .encrypt_device(path, Some(&header_path), passphrase.clone())
            .unwrap();

        std::fs::remove_file(&header_path).unwrap();

        let result =
            luks2_formatter.open_device(path, Some(header_path.as_str()), NAME, passphrase);
        assert!(result.is_err());
    }

    #[test]
    fn prepare_luks_header_file_rejects_existing_path() {
        use rand::{distr::Alphanumeric, rng, RngExt};

        let path_str = format!(
            "/dev/{}",
            rng()
                .sample_iter(&Alphanumeric)
                .take(16)
                .map(char::from)
                .collect::<String>()
        );

        let header_path = luks_header_path(&path_str);
        prepare_luks_header_file(&header_path).unwrap();
        let result = prepare_luks_header_file(&header_path);

        match result {
            Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists),
            other => panic!("unexpected result: {other:?}"),
        }
        let _ = std::fs::remove_file(&header_path);
    }

    /// This test can be used to clean useless devices under /dev/mapper/
    #[ignore]
    #[test]
    fn create_encrypt_close_test() {
        let luks2_formatter = Luks2Formatter { integrity: false };
        luks2_formatter
            .close_device("d7920c40-e7dc-48a4-aff7-6eab51c7d2d5")
            .unwrap();
    }
}
