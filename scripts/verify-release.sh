#!/usr/bin/env bash
# Verify a scadenza release end to end. This automates the manual steps of
# docs/install.md: download the release assets, check the cosign bundle over
# checksums.txt, compare the archive checksum, validate the SPDX SBOM, verify
# the GitHub build provenance attestation and run the binary.
#
# Usage: scripts/verify-release.sh <tag> [options]
#
#   --os OS            target OS (linux, darwin, windows); default: this machine
#   --arch ARCH        target CPU (amd64, arm64); default: this machine
#   --repo OWNER/NAME  GitHub repository; default: HarnageaGabriel/scadenza
#   --dir DIR          download directory; default: a temporary directory that
#                      is removed on exit
#   --gh-download      download with gh instead of curl (needed for drafts)
#   --allow-missing-gh do not fail the run when gh is not installed
#   --self-test        run the offline argument validation self test
#   -h, --help         print this help
#
# Exit codes: 0 every check passed, 1 a check failed, 2 invalid arguments,
# 3 a required tool is missing.
set -euo pipefail

PROGRAM=${0##*/}
REPO_DEFAULT='HarnageaGabriel/scadenza'
MODULE_PATH='github.com/HarnageaGabriel/scadenza'
OIDC_ISSUER='https://token.actions.githubusercontent.com'
EXIT_FAILED=1
EXIT_USAGE=2
EXIT_MISSING_TOOL=3

TAG=''
OS=''
ARCH=''
REPO="$REPO_DEFAULT"
DOWNLOAD_DIR=''
USE_GH=0
ALLOW_MISSING_GH=0
SELF_TEST=0

WORKDIR=''
ARCHIVE=''
CHECKSUMS='checksums.txt'
BUNDLE='checksums.txt.bundle'
SBOM=''
HOST_OS=''
HOST_ARCH=''
STEP_MESSAGE=''
STEP_FAILURES=0

usage() {
  cat <<EOF
Usage: ${PROGRAM} <tag> [options]

Verify a scadenza release: signature, checksums, SBOM, build provenance and
the binary itself. See docs/install.md for the manual equivalent.

Options:
  --os OS            target OS (linux, darwin, windows); default: this machine
  --arch ARCH        target CPU (amd64, arm64); default: this machine
  --repo OWNER/NAME  GitHub repository; default: ${REPO_DEFAULT}
  --dir DIR          download directory; default: a temporary directory that
                     is removed on exit
  --gh-download      download with gh instead of curl (needed for draft
                     releases, which are not reachable over plain HTTPS)
  --allow-missing-gh do not fail the run when gh is not installed
  --self-test        run the offline argument validation self test
                     (the bare word "self-test" does the same)
  -h, --help         print this help
EOF
}

die_usage() {
  printf 'error: %s\n' "$1" >&2
  printf 'Run %s --help for usage.\n' "$PROGRAM" >&2
  exit "$EXIT_USAGE"
}

host_os() {
  case "$(uname -s)" in
  Linux) printf 'linux\n' ;;
  Darwin) printf 'darwin\n' ;;
  MINGW* | MSYS* | CYGWIN* | Windows_NT) printf 'windows\n' ;;
  *) printf 'unknown\n' ;;
  esac
}

host_arch() {
  case "$(uname -m)" in
  x86_64 | amd64) printf 'amd64\n' ;;
  aarch64 | arm64) printf 'arm64\n' ;;
  *) printf 'unknown\n' ;;
  esac
}

# The validators return 0 for an accepted value and 1 for a rejected one, so
# the self test can exercise them without exiting.
valid_tag() {
  grep -Eq -- '^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$' <<<"$1"
}

valid_repo() {
  grep -Eq -- '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$' <<<"$1"
}

valid_os() {
  case "$1" in
  linux | darwin | windows) return 0 ;;
  *) return 1 ;;
  esac
}

valid_arch() {
  case "$1" in
  amd64 | arm64) return 0 ;;
  *) return 1 ;;
  esac
}

require_valid_tag() {
  if ! valid_tag "$1"; then
    die_usage "invalid tag: '$1' (expected v1.2.3 or v1.2.3-rc.1)"
  fi
}

require_valid_repo() {
  if ! valid_repo "$1"; then
    die_usage "invalid repo: '$1' (expected owner/name)"
  fi
}

require_valid_os() {
  if ! valid_os "$1"; then
    die_usage "invalid os: '$1' (expected linux, darwin or windows)"
  fi
}

require_valid_arch() {
  if ! valid_arch "$1"; then
    die_usage "invalid arch: '$1' (expected amd64 or arm64)"
  fi
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
    --os)
      [ $# -ge 2 ] || die_usage '--os needs a value'
      OS=$2
      shift 2
      ;;
    --arch)
      [ $# -ge 2 ] || die_usage '--arch needs a value'
      ARCH=$2
      shift 2
      ;;
    --repo)
      [ $# -ge 2 ] || die_usage '--repo needs a value'
      REPO=$2
      shift 2
      ;;
    --dir)
      [ $# -ge 2 ] || die_usage '--dir needs a value'
      DOWNLOAD_DIR=$2
      shift 2
      ;;
    --gh-download)
      USE_GH=1
      shift
      ;;
    --allow-missing-gh)
      ALLOW_MISSING_GH=1
      shift
      ;;
    --self-test)
      SELF_TEST=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      die_usage "unknown option: '$1'"
      ;;
    *)
      if [ -z "$TAG" ] && [ "$1" = 'self-test' ]; then
        SELF_TEST=1
      elif [ -z "$TAG" ]; then
        TAG=$1
      else
        die_usage "unexpected argument: '$1'"
      fi
      shift
      ;;
    esac
  done
}

print_install_hints() {
  printf 'Install hints:\n' >&2
  case "$1" in
  *curl*) printf '  curl:       https://curl.se/download.html (apt install curl, brew install curl)\n' >&2 ;;
  esac
  case "$1" in
  *sha256sum*)
    printf '  sha256sum:  Debian/Ubuntu (apt install coreutils) or macOS (brew install coreutils); shasum -a 256 also works\n' >&2
    ;;
  esac
  case "$1" in
  *cosign*) printf '  cosign:     go install github.com/sigstore/cosign/v2/cmd/cosign@latest\n' >&2 ;;
  esac
  case "$1" in
  *jq*) printf '  jq:         https://jqlang.github.io/jq/download/ (apt install jq, brew install jq)\n' >&2 ;;
  esac
  case "$1" in
  *gh*) printf '  gh:         https://cli.github.com (apt install gh, brew install gh)\n' >&2 ;;
  esac
}

check_tools() {
  missing=''
  if ! command -v curl >/dev/null 2>&1; then
    missing="${missing} curl"
  fi
  if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    missing="${missing} sha256sum"
  fi
  if ! command -v cosign >/dev/null 2>&1; then
    missing="${missing} cosign"
  fi
  if ! command -v jq >/dev/null 2>&1; then
    missing="${missing} jq"
  fi
  if ! command -v gh >/dev/null 2>&1; then
    if [ "$USE_GH" -eq 1 ]; then
      missing="${missing} gh"
    else
      printf 'WARNING: gh is not installed, so the build provenance attestation will NOT be verified.\n' >&2
      printf 'WARNING: install gh (https://cli.github.com) and rerun, or pass --allow-missing-gh to accept the missing check.\n' >&2
    fi
  fi
  if [ -n "$missing" ]; then
    printf 'error: missing required tools:%s\n' "$missing" >&2
    print_install_hints "$missing"
    exit "$EXIT_MISSING_TOOL"
  fi
}

setup_workdir() {
  if [ -n "$DOWNLOAD_DIR" ]; then
    if ! mkdir -p "$DOWNLOAD_DIR"; then
      printf 'error: cannot create the download directory: %s\n' "$DOWNLOAD_DIR" >&2
      exit "$EXIT_USAGE"
    fi
    WORKDIR=$DOWNLOAD_DIR
    return 0
  fi
  if ! WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/scadenza-verify.XXXXXX"); then
    printf 'error: cannot create a temporary directory\n' >&2
    exit "$EXIT_FAILED"
  fi
  trap 'rm -rf "$WORKDIR"' EXIT
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# Prints "<count> <sha256>" for the archive line of checksums.txt.
checksum_entry() {
  awk -v f="$1" '
    {
      name = $2
      sub(/^\*/, "", name)
      if (name == f) {
        count++
        sha = $1
      }
    }
    END { printf "%d %s\n", count + 0, sha }
  ' "$2"
}

step_download() {
  STEP_MESSAGE="downloaded ${ARCHIVE}, ${CHECKSUMS}, ${BUNDLE} and ${SBOM}"
  local base="https://github.com/${REPO}/releases/download/${TAG}"
  local f
  local failed=''
  for f in "$ARCHIVE" "$CHECKSUMS" "$BUNDLE" "$SBOM"; do
    if [ "$USE_GH" -eq 1 ]; then
      if ! gh release download "$TAG" --repo "$REPO" --dir "$WORKDIR" --pattern "$f"; then
        failed="${failed} ${f}"
      fi
    else
      if ! curl -fL -sS --retry 3 -o "${WORKDIR}/${f}" "${base}/${f}"; then
        failed="${failed} ${f}"
      fi
    fi
  done
  if [ -n "$failed" ]; then
    STEP_MESSAGE="could not download:${failed}"
    return 1
  fi
  for f in "$ARCHIVE" "$CHECKSUMS" "$BUNDLE" "$SBOM"; do
    if [ ! -s "${WORKDIR}/${f}" ]; then
      STEP_MESSAGE="the downloaded asset ${f} is missing or empty"
      return 1
    fi
  done
  return 0
}

step_cosign() {
  STEP_MESSAGE="the cosign bundle over ${CHECKSUMS} is signed by the release workflow"
  local identity="https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${TAG}"
  if ! cosign verify-blob \
    --bundle "${WORKDIR}/${BUNDLE}" \
    --certificate-identity "$identity" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    "${WORKDIR}/${CHECKSUMS}"; then
    STEP_MESSAGE="the cosign bundle over ${CHECKSUMS} is not signed by ${identity}"
    return 1
  fi
  return 0
}

step_checksum() {
  STEP_MESSAGE="the SHA-256 of ${ARCHIVE} matches its line in ${CHECKSUMS}"
  local entry count sha actual
  if ! entry=$(checksum_entry "$ARCHIVE" "${WORKDIR}/${CHECKSUMS}"); then
    STEP_MESSAGE="cannot read ${CHECKSUMS}"
    return 1
  fi
  count=${entry%% *}
  sha=${entry#* }
  if [ "$count" = '0' ]; then
    STEP_MESSAGE="${CHECKSUMS} has no line for ${ARCHIVE}"
    return 1
  fi
  if [ "$count" != '1' ]; then
    STEP_MESSAGE="${CHECKSUMS} has ${count} lines for ${ARCHIVE}, expected exactly one"
    return 1
  fi
  if ! actual=$(sha256_of "${WORKDIR}/${ARCHIVE}"); then
    STEP_MESSAGE="cannot compute the SHA-256 of ${ARCHIVE}"
    return 1
  fi
  if [ "$actual" != "$sha" ]; then
    STEP_MESSAGE="the SHA-256 of ${ARCHIVE} is ${actual} but ${CHECKSUMS} says ${sha}"
    return 1
  fi
  return 0
}

step_sbom() {
  STEP_MESSAGE="the SBOM is SPDX JSON and mentions ${MODULE_PATH}"
  local sbom_file="${WORKDIR}/${SBOM}"
  if ! jq -e '.spdxVersion' "$sbom_file" >/dev/null 2>&1; then
    STEP_MESSAGE="${SBOM} is not a valid SPDX JSON document"
    return 1
  fi
  if jq -e '[.packages[]? |
    select(((.name // "") + " " + (.purl // "") + " " + (.supplier // "")) |
    test("scadenza"; "i"))] | length > 0' "$sbom_file" >/dev/null 2>&1; then
    return 0
  fi
  if grep -qi 'scadenza' "$sbom_file"; then
    return 0
  fi
  STEP_MESSAGE="${SBOM} does not mention ${MODULE_PATH}"
  return 1
}

step_attestation() {
  if ! command -v gh >/dev/null 2>&1; then
    if [ "$ALLOW_MISSING_GH" -eq 1 ]; then
      STEP_MESSAGE="gh is not installed, so the build provenance of ${ARCHIVE} was NOT verified"
      return 2
    fi
    STEP_MESSAGE="gh is not installed, so the build provenance of ${ARCHIVE} was NOT verified"
    return 1
  fi
  STEP_MESSAGE="the build provenance of ${ARCHIVE} is verified"
  if ! gh attestation verify "${WORKDIR}/${ARCHIVE}" --repo "$REPO" \
    --signer-workflow "${REPO}/.github/workflows/release.yml"; then
    STEP_MESSAGE="the build provenance of ${ARCHIVE} is missing or invalid"
    return 1
  fi
  return 0
}

step_binary() {
  local extract_dir binary output
  if [ "$OS" != "$HOST_OS" ] || [ "$ARCH" != "$HOST_ARCH" ]; then
    STEP_MESSAGE="skipped (different platform): the archive targets ${OS}/${ARCH}, this machine is ${HOST_OS}/${HOST_ARCH}"
    return 2
  fi
  STEP_MESSAGE="the extracted binary reports its version"
  extract_dir="${WORKDIR}/extract"
  if ! mkdir -p "$extract_dir"; then
    STEP_MESSAGE="cannot create the extraction directory"
    return 1
  fi
  case "$ARCHIVE" in
  *.zip)
    if ! unzip -q -o "${WORKDIR}/${ARCHIVE}" -d "$extract_dir"; then
      STEP_MESSAGE="cannot extract ${ARCHIVE}"
      return 1
    fi
    ;;
  *)
    if ! tar -xzf "${WORKDIR}/${ARCHIVE}" -C "$extract_dir"; then
      STEP_MESSAGE="cannot extract ${ARCHIVE}"
      return 1
    fi
    ;;
  esac
  if [ "$OS" = 'windows' ]; then
    binary="${extract_dir}/scadenza.exe"
  else
    binary="${extract_dir}/scadenza"
  fi
  if [ ! -f "$binary" ]; then
    STEP_MESSAGE="the archive does not contain ${binary##*/}"
    return 1
  fi
  chmod +x "$binary" 2>/dev/null || true
  if ! output=$("$binary" version 2>&1); then
    printf '%s\n' "$output" >&2
    STEP_MESSAGE="the extracted binary failed to run"
    return 1
  fi
  printf '%s\n' "$output"
  return 0
}

run_step() {
  local status
  STEP_MESSAGE=''
  if "$1"; then
    status=0
  else
    status=$?
  fi
  case "$status" in
  0)
    printf 'PASS: %s\n' "$STEP_MESSAGE"
    ;;
  2)
    printf 'SKIP: %s\n' "$STEP_MESSAGE"
    ;;
  *)
    printf 'FAIL: %s\n' "$STEP_MESSAGE"
    STEP_FAILURES=$((STEP_FAILURES + 1))
    ;;
  esac
}

# Offline self test: the argument validation must reject malformed input with
# a non-zero exit code and must not reach the network.
self_test() {
  local cases_run=0
  local cases_failed=0
  local tmp bash_bin
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/scadenza-selftest.XXXXXX")
  bash_bin=${BASH:-bash}

  accept() {
    cases_run=$((cases_run + 1))
    if "$@"; then
      printf 'PASS: accepted %s\n' "$2"
    else
      printf 'FAIL: rejected the valid value %s\n' "$2"
      cases_failed=$((cases_failed + 1))
    fi
  }

  reject() {
    cases_run=$((cases_run + 1))
    if "$@"; then
      printf 'FAIL: accepted the invalid value %s\n' "$2"
      cases_failed=$((cases_failed + 1))
    else
      printf 'PASS: rejected %s\n' "$2"
    fi
  }

  # The validators, in process.
  accept valid_tag 'v1.2.3'
  accept valid_tag 'v0.0.0-rc.1'
  accept valid_tag 'v10.20.30-beta.2'
  accept valid_repo 'HarnageaGabriel/scadenza'
  accept valid_repo 'owner.name/repo_name-1'
  accept valid_os 'linux'
  accept valid_os 'darwin'
  accept valid_os 'windows'
  accept valid_arch 'amd64'
  accept valid_arch 'arm64'

  reject valid_tag '1.2.3'
  reject valid_tag 'v1.2'
  reject valid_tag 'v1.2.3.4'
  reject valid_tag 'v1.2.3-'
  reject valid_tag 'v1.2.3-rc_1'
  reject valid_tag 'v1.2.3/../x'
  reject valid_tag ''
  reject valid_repo 'owner'
  reject valid_repo 'owner/name/extra'
  reject valid_repo 'own er/name'
  reject valid_repo 'owner/name!'
  reject valid_os 'solaris'
  reject valid_arch 'mips64'

  # The script itself, out of process: a non-zero exit code for bad input.
  for bad_args in 'v1.2' '1.2.3' 'v1.2.3-'; do
    cases_run=$((cases_run + 1))
    if "$bash_bin" "$0" "$bad_args" --dir "$tmp" >/dev/null 2>&1; then
      printf 'FAIL: the script accepted the invalid tag %s\n' "$bad_args"
      cases_failed=$((cases_failed + 1))
    else
      printf 'PASS: the script rejected the invalid tag %s\n' "$bad_args"
    fi
  done
  for bad_args in '--repo owner/name/extra' '--repo owner' '--os solaris' '--arch mips64'; do
    cases_run=$((cases_run + 1))
    # shellcheck disable=SC2086
    if "$bash_bin" "$0" v1.2.3 $bad_args --dir "$tmp" >/dev/null 2>&1; then
      printf 'FAIL: the script accepted the invalid arguments %s\n' "$bad_args"
      cases_failed=$((cases_failed + 1))
    else
      printf 'PASS: the script rejected the invalid arguments %s\n' "$bad_args"
    fi
  done

  # Nothing was downloaded: the rejected runs never reached the network.
  cases_run=$((cases_run + 1))
  if [ ! -d "$tmp" ] || [ -n "$(ls -A "$tmp" 2>/dev/null)" ]; then
    printf 'FAIL: the rejected runs wrote to the download directory\n'
    cases_failed=$((cases_failed + 1))
  else
    printf 'PASS: the rejected runs did not reach the network\n'
  fi
  rm -rf "$tmp"

  printf 'self test: %d cases, %d failed\n' "$cases_run" "$cases_failed"
  if [ "$cases_failed" -ne 0 ]; then
    return 1
  fi
  return 0
}

main() {
  parse_args "$@"

  if [ "$SELF_TEST" -eq 1 ]; then
    if self_test; then
      exit 0
    fi
    exit 1
  fi

  [ -n "$TAG" ] || die_usage 'a tag is required (for example v0.1.0)'
  require_valid_tag "$TAG"
  require_valid_repo "$REPO"
  if [ -z "$OS" ]; then
    OS=$(host_os)
    if [ "$OS" = 'unknown' ]; then
      die_usage 'cannot detect the operating system, pass --os'
    fi
  fi
  require_valid_os "$OS"
  if [ -z "$ARCH" ]; then
    ARCH=$(host_arch)
    if [ "$ARCH" = 'unknown' ]; then
      die_usage 'cannot detect the CPU architecture, pass --arch'
    fi
  fi
  require_valid_arch "$ARCH"

  HOST_OS=$(host_os)
  HOST_ARCH=$(host_arch)

  version_number=${TAG#v}
  if [ "$OS" = 'windows' ]; then
    extension='zip'
  else
    extension='tar.gz'
  fi
  ARCHIVE="scadenza_${version_number}_${OS}_${ARCH}.${extension}"
  SBOM="${ARCHIVE}.sbom.json"

  printf 'Verifying %s (%s) of %s\n' "$TAG" "$OS/$ARCH" "$REPO"

  check_tools
  setup_workdir
  printf 'Download directory: %s\n' "$WORKDIR"

  run_step step_download
  run_step step_cosign
  run_step step_checksum
  run_step step_sbom
  run_step step_attestation
  run_step step_binary

  printf '\n'
  if [ "$STEP_FAILURES" -eq 0 ]; then
    printf 'All checks passed for %s (%s).\n' "$TAG" "$OS/$ARCH"
    exit 0
  fi
  printf '%d check(s) failed for %s (%s).\n' "$STEP_FAILURES" "$TAG" "$OS/$ARCH"
  exit "$EXIT_FAILED"
}

main "$@"
