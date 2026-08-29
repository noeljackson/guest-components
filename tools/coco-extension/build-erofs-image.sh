#!/usr/bin/env bash
#
# Copyright (c) 2026 Confidential Containers contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# Turn the assembled CoCo extension rootfs into the image layout consumed by
# kata's guest extension mount path:
#
#   partition 1: EROFS payload
#   partition 2: dm-verity hash device
#   root_hash_coco-extension.txt: kernel cmdline verity parameters
#
# This intentionally builds the small extension image locally instead of pulling
# in kata-containers' osbuilder. The important compatibility points are the disk
# layout, the EROFS options, and veritysetup's --no-superblock format.
#
# Requires root privileges for loop devices and dm-verity formatting.
set -o errexit
set -o nounset
set -o pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root_dir="$(cd "${script_dir}/../.." && pwd)"

ARCH="${ARCH:-$(uname -m)}"

# Assembled rootfs (output of assemble-rootfs.sh).
ROOTFS_DIR="${ROOTFS_DIR:-${repo_root_dir}/build/coco-extension-rootfs}"

# Where the resulting image and root hash file are written.
OUTPUT_DIR="${OUTPUT_DIR:-${repo_root_dir}/build/coco-extension-image}"

BUILD_VARIANT="coco-extension"
IMAGE_NAME="kata-containers-${BUILD_VARIANT}.img"
ROOTFS_START_MB=1
IMAGE_SIZE_ALIGNMENT_MB="${IMAGE_SIZE_ALIGNMENT_MB:-128}"

info() { echo "[build-erofs-image] $*"; }
die() { echo "[build-erofs-image] ERROR: $*" >&2; exit 1; }

has_executable_mode() {
	local mode
	[[ -f "$1" ]] || return 1
	mode="$(stat -c '%a' -- "$1")" || return 1
	(( (8#${mode} & 0111) != 0 ))
}

[[ -d "${ROOTFS_DIR}" ]] || die "rootfs not found at ${ROOTFS_DIR}; run assemble-rootfs.sh first"
if [[ "${EUID}" -ne 0 ]]; then
	command -v sudo >/dev/null 2>&1 || die "root privileges are required and sudo is not available"
	exec sudo -E bash "$0" "$@"
fi

for cmd in cmp cp dd fsck.erofs losetup mkfs.erofs parted partprobe sed stat truncate udevadm veritysetup; do
	command -v "${cmd}" >/dev/null 2>&1 || die "${cmd} is required"
done

cleanup_paths=()
loop_device=""

cleanup() {
	if [[ -n "${loop_device}" ]]; then
		losetup -d "${loop_device}" >/dev/null 2>&1 || true
	fi

	for path in "${cleanup_paths[@]}"; do
		rm -rf "${path}"
	done
}
trap cleanup EXIT

make_erofs_payload() {
	local staging_dir="$1"
	local fs_image="$2"

	info "Copying extension rootfs into staging directory"
	cp -a "${ROOTFS_DIR}"/. "${staging_dir}/"

	# kata's osbuilder creates this whenever /etc exists. It is harmless for the
	# extension and keeps this image layout compatible with the existing asset.
	if [[ -d "${staging_dir}/etc" ]]; then
		touch "${staging_dir}/etc/machine-id"
	fi

	info "Creating EROFS payload"
	mkfs.erofs -zlz4hc -Enoinline_data "${fs_image}" "${staging_dir}"
}

calculate_image_size_mb() {
	local fs_image="$1"
	local fs_size_bytes
	local image_size_mb
	local remainder

	fs_size_bytes="$(stat -c "%s" "${fs_image}")"
	image_size_mb=$(( ((fs_size_bytes + 1048576) / 1048576) + 1 + ROOTFS_START_MB ))

	# Reserve the final ~1% of the disk for the dm-verity hash partition,
	# matching kata's osbuilder layout.
	image_size_mb=$(( (image_size_mb * 100 / 99) + 1 ))

	remainder=$(( image_size_mb % IMAGE_SIZE_ALIGNMENT_MB ))
	if [[ "${remainder}" != "0" ]]; then
		image_size_mb=$(( image_size_mb + IMAGE_SIZE_ALIGNMENT_MB - remainder ))
	fi

	echo "${image_size_mb}"
}

create_disk() {
	local image="$1"
	local image_size_mb="$2"
	local hash_start_mb

	info "Creating raw disk image (${image_size_mb} MiB)"
	rm -f "${image}"
	truncate -s "${image_size_mb}M" "${image}"

	hash_start_mb=$(( image_size_mb * 99 / 100 ))
	if [[ "${hash_start_mb}" -le "${ROOTFS_START_MB}" ]]; then
		die "image too small for dm-verity two-partition layout"
	fi

	parted -s -a optimal "${image}" -- \
		mklabel msdos \
		mkpart primary ext4 "${ROOTFS_START_MB}MiB" "${hash_start_mb}MiB" \
		mkpart primary ext4 "${hash_start_mb}MiB" 100% \
		set 1 boot on
}

attach_loop_device() {
	local image="$1"
	local device

	device="$(losetup -P -f --show "${image}")"
	# Own the loop device as soon as losetup succeeds. A partition-discovery
	# timeout must still detach it through the EXIT trap.
	loop_device="${device}"
	partprobe -s "${device}" >/dev/null
	# Partition device nodes are created asynchronously by udev and can lag
	# behind partprobe on a busy host. Wait for the second (last) partition,
	# then retain a bounded poll as a fallback for delayed device-node creation.
	udevadm settle --timeout=30 --exit-if-exists="${device}p2" || true

	for _ in $(seq 1 30); do
		if [[ -b "${device}p1" && -b "${device}p2" ]]; then
			return
		fi
		sleep 1
	done

	die "partitions ${device}p1 and ${device}p2 were not created"
}

build_kernel_verity_params() {
	local output="$1"
	local root_hash
	local salt
	local data_blocks
	local data_block_size
	local hash_block_size

	read_verity_field() {
		local label="$1"
		local value

		value="$(printf '%s\n' "${output}" | sed -n "s/^${label}:[[:space:]]*//p")"
		value="${value// \[*/}"
		[[ -n "${value}" ]] || die "Missing '${label}' in veritysetup output"
		echo "${value}"
	}

	root_hash="$(read_verity_field "Root hash")"
	salt="$(read_verity_field "Salt")"
	data_blocks="$(read_verity_field "Data blocks")"
	data_block_size="$(read_verity_field "Data block size")"
	hash_block_size="$(read_verity_field "Hash block size")"

	printf 'root_hash=%s,salt=%s,data_blocks=%s,data_block_size=%s,hash_block_size=%s' \
		"${root_hash}" \
		"${salt}" \
		"${data_blocks}" \
		"${data_block_size}" \
		"${hash_block_size}"
}

setup_verity() {
	local device="$1"
	local root_hash_file="$2"
	local verity_output
	local kernel_verity_params

	[[ -b "${device}p2" ]] || die "expected dm-verity hash partition ${device}p2"

	info "Formatting dm-verity hash device"
	verity_output="$(veritysetup format --no-superblock "${device}p1" "${device}p2" 2>&1)"
	kernel_verity_params="$(build_kernel_verity_params "${verity_output}")"
	printf '%s\n' "${kernel_verity_params}" > "${root_hash_file}"
}

verify_erofs_payload() {
	local device="$1"
	local extracted_dir
	local extracted_root
	local expected_cdh="${ROOTFS_DIR}/usr/local/bin/confidential-data-hub"
	local actual_cdh

	has_executable_mode "${expected_cdh}" || \
		die "assembled rootfs lacks executable confidential-data-hub"
	extracted_root="$(mktemp -p "${TMPDIR:-/tmp}" -d coco-extension-image.XXXXXX)"
	cleanup_paths+=("${extracted_root}")
	extracted_dir="${extracted_root}/rootfs"
	fsck.erofs --extract="${extracted_dir}" "${device}p1" >/dev/null
	actual_cdh="${extracted_dir}/usr/local/bin/confidential-data-hub"
	has_executable_mode "${actual_cdh}" || \
		die "EROFS payload lacks executable confidential-data-hub"
	cmp -s "${expected_cdh}" "${actual_cdh}" || \
		die "EROFS confidential-data-hub differs from the assembled rootfs"
	info "Verified confidential-data-hub in the EROFS payload"
}

build_image() {
	local image="${OUTPUT_DIR}/${IMAGE_NAME}"
	local root_hash_file="${OUTPUT_DIR}/root_hash_${BUILD_VARIANT}.txt"
	local staging_dir
	local fs_image
	local image_size_mb
	local device

	mkdir -p "${OUTPUT_DIR}"
	staging_dir="$(mktemp -p "${TMPDIR:-/tmp}" -d coco-extension-image.XXXXXX)"
	cleanup_paths+=("${staging_dir}")
	fs_image="$(mktemp -p "${TMPDIR:-/tmp}" coco-extension-erofs.XXXXXX)"
	cleanup_paths+=("${fs_image}")

	info "Building ${IMAGE_NAME} (ARCH=${ARCH})"
	make_erofs_payload "${staging_dir}" "${fs_image}"
	image_size_mb="$(calculate_image_size_mb "${fs_image}")"
	create_disk "${image}" "${image_size_mb}"
	attach_loop_device "${image}"
	device="${loop_device}"

	info "Writing EROFS payload to ${device}p1"
	dd if="${fs_image}" of="${device}p1" bs=4M conv=fsync status=none
	verify_erofs_payload "${device}"

	setup_verity "${device}" "${root_hash_file}"

	info "Root hash / verity params:"
	sed 's/^/  /' "${root_hash_file}"

	info "Image built: ${image}"
}

main() {
	build_image
}

main "$@"
