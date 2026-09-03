#!/usr/bin/env bash
# shellcheck disable=SC2016 # Contract literals intentionally contain workflow variables.
# Copyright (c) 2026 Confidential Containers contributors
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
workflow="${repo_root}/.github/workflows/coco-extension-image.yml"
dockerfile="${script_dir}/Dockerfile"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/coco-publication-contract.XXXXXX")"

cleanup() {
	find "${test_root}" -depth -delete 2>/dev/null || true
}
trap cleanup EXIT

push_branches() {
	awk '
		/^  push:$/ { in_push = 1; next }
		in_push && /^    branches:$/ { in_branches = 1; next }
		in_branches && /^    - / {
			sub(/^    - /, "")
				gsub(/"/, "")
			print
			next
		}
		in_branches { exit }
	' "$1"
}

require_line() {
	local file=$1
	local line=$2
	local description=$3
	grep -Fqx -- "${line}" "${file}" || {
		printf 'missing %s in %s\n' "${description}" "${file}" >&2
		return 1
	}
}

require_text() {
	local file=$1
	local text=$2
	local description=$3
	grep -Fq -- "${text}" "${file}" || {
		printf 'missing %s in %s\n' "${description}" "${file}" >&2
		return 1
	}
}

verify_contract() {
	local candidate=$1
	local branches
	branches="$(push_branches "${candidate}")"
	[[ "$(grep -Fxc main <<<"${branches}")" -eq 1 ]] || {
		printf 'publication workflow must select main exactly once\n' >&2
		return 1
	}
	[[ "$(grep -Fxc downstream/confidential-storage <<<"${branches}")" -eq 1 ]] || {
		printf 'publication workflow must select downstream/confidential-storage exactly once\n' >&2
		return 1
	}
	[[ "$(wc -l <<<"${branches}")" -eq 2 ]] || {
		printf 'publication workflow must select only main and downstream/confidential-storage\n' >&2
		return 1
	}
	if grep -Fq 'workflow_dispatch:' "${candidate}"; then
		printf 'publication workflow must not expose manual dispatch\n' >&2
		return 1
	fi
	if grep -Eq '^[[:space:]]+ref:' "${candidate}"; then
		printf 'publication checkout must use the event exact commit\n' >&2
		return 1
	fi

	require_line "${candidate}" \
		'        SOURCE_REPOSITORY: ${{ github.server_url }}/${{ github.repository }}' \
		'exact source repository binding'
	require_text "${candidate}" \
		'--build-arg "SOURCE_REVISION=${GIT_SHA}"' \
		'exact source revision binding'
	require_line "${candidate}" \
		'        arch_tag="${GIT_SHA}-${VARIANT}-${OCI_ARCH}"' \
		'immutable per-architecture tag'
	require_line "${candidate}" \
		"        EXTRA_TAG: \${{ github.event_name == 'release' && github.event.release.tag_name || (github.ref == 'refs/heads/main' && 'latest' || '') }}" \
		'main-only rolling tag condition'
	require_line "${candidate}" \
		'          tags=("${GIT_SHA}-${VARIANT}")' \
		'immutable multi-architecture tag'
	require_line "${candidate}" \
		'    - name: Generate provenance for the OCI container image' \
		'OCI provenance attestation'
	require_line "${candidate}" \
		'    - name: Generate SBOM attestation for the OCI container image' \
		'OCI SBOM attestation'

	require_text "${dockerfile}" \
		'org.opencontainers.image.source="${SOURCE_REPOSITORY}"' \
		'OCI source repository label'
	require_text "${dockerfile}" \
		'org.opencontainers.image.revision="${SOURCE_REVISION}"' \
		'OCI source revision label'
}

# Reproduce the original fork mismatch: a main-only workflow must be rejected.
stale_workflow="${test_root}/main-only.yml"
sed '/^    - downstream\/confidential-storage$/d' "${workflow}" >"${stale_workflow}"
if verify_contract "${stale_workflow}" >/dev/null 2>&1; then
	printf 'main-only publication fixture unexpectedly satisfied the contract\n' >&2
	exit 1
fi

# The upstreamable source branch must never become a publication trigger.
source_trigger_workflow="${test_root}/source-trigger.yml"
sed '/^    - downstream\/confidential-storage$/a\    - downstream/confidential-storage-source' \
	"${workflow}" >"${source_trigger_workflow}"
if verify_contract "${source_trigger_workflow}" >/dev/null 2>&1; then
	printf 'source-branch publication fixture unexpectedly satisfied the contract\n' >&2
	exit 1
fi

# Deployment must build the immutable event commit, not a moving source branch.
moving_source_workflow="${test_root}/moving-source.yml"
sed '/^        persist-credentials: false$/a\        ref: downstream/confidential-storage-source' \
	"${workflow}" >"${moving_source_workflow}"
if verify_contract "${moving_source_workflow}" >/dev/null 2>&1; then
	printf 'moving-source checkout fixture unexpectedly satisfied the contract\n' >&2
	exit 1
fi

verify_contract "${workflow}"
printf 'downstream immutable publication contract: PASS\n'
