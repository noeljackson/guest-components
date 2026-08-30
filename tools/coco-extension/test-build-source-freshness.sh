#!/usr/bin/env bash
# Copyright (c) 2026 Confidential Containers contributors
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/coco-build-freshness.XXXXXX")"

cleanup() {
	find "${test_root}" -depth -delete 2>/dev/null || true
}
trap cleanup EXIT

build_dir="${test_root}/target/x86_64-unknown-linux-gnu/release"
mkdir -p "${build_dir}"
touch \
	"${build_dir}/confidential-data-hub" \
	"${build_dir}/attestation-agent" \
	"${build_dir}/api-server-rest"

output="$(
	make -n -C "${repo_root}" \
		MAKE=: \
		BUILD_DIR="${build_dir}" \
		ARCH=x86_64 \
		LIBC=gnu \
		build
)"

for component in confidential-data-hub api-server-rest attestation-agent; do
	count="$(grep -Fc "cd ${component} && :" <<<"${output}")"
	[[ "${count}" -eq 1 ]] || {
		printf 'expected one current-source build dispatch for %s, got %s\n' \
			"${component}" "${count}" >&2
		exit 1
	}
done

printf 'current-source guest-component build dispatch: PASS\n'
