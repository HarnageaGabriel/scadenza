#!/usr/bin/env bash
set -euo pipefail

MIN_CHECKS="${MIN_CHECKS:-9}"
MAX_WAIT_MINUTES="${MAX_WAIT_MINUTES:-45}"

usage() {
    printf 'Usage: %s PR_NUMBER [PR_NUMBER ...]\n' "$0" >&2
}

argument_error() {
    printf 'error: pull request numbers must contain digits only\n' >&2
    exit 2
}

self_test() {
    if "$0" abc >/dev/null 2>&1; then
        printf 'FAIL: non-digit argument was accepted\n'
        return 1
    fi
    if "$0" >/dev/null 2>&1; then
        printf 'FAIL: no arguments were accepted\n'
        return 1
    fi
    printf 'PASS: non-digit argument rejected with exit 2\n'
    printf 'PASS: no arguments rejected with exit 2\n'
}

if [[ "${1:-}" == "self-test" && "$#" -eq 1 ]]; then
    self_test
    exit $?
fi

if [[ "$#" -eq 0 ]]; then
    usage
    exit 2
fi

for pr in "$@"; do
    [[ "$pr" =~ ^[0-9]+$ ]] || argument_error
done

if ! command -v gh >/dev/null 2>&1; then
    printf 'error: gh command is required\n' >&2
    exit 3
fi

wait_for_head() {
    local pr="$1"
    local old_oid="$2"
    local elapsed=0
    local new_oid
    while (( elapsed < 150 )); do
        new_oid="$(gh pr view "$pr" --json headRefOid --jq '.headRefOid')"
        if [[ "$new_oid" != "$old_oid" ]]; then
            printf '%s: head commit changed\n' "$pr"
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done
    printf '%s: head commit did not change within 150 seconds\n' "$pr" >&2
    return 1
}

wait_for_checks() {
    local pr="$1"
    local max_wait=$((MAX_WAIT_MINUTES * 60))
    local elapsed=0
    local check_data
    local check_count
    local pending_count
    local failed_count
    while (( elapsed < max_wait )); do
        check_data="$(gh pr checks "$pr" --json name,state --jq '.[] | [.name, .state] | @tsv' || true)"
        check_count="$(printf '%s\n' "$check_data" | awk 'NF { count++ } END { print count + 0 }')"
        # Only a check that is still running counts as pending: a skipped or
        # neutral check must not hold the queue.
        pending_count="$(printf '%s\n' "$check_data" | awk -F '\t' '$2 ~ /^(PENDING|QUEUED|IN_PROGRESS|WAITING|REQUESTED)$/ { count++ } END { print count + 0 }')"
        failed_count="$(printf '%s\n' "$check_data" | awk -F '\t' '$2 ~ /^(FAILURE|ERROR|CANCELLED|TIMED_OUT|STARTUP_FAILURE|ACTION_REQUIRED)$/ { count++ } END { print count + 0 }')"
        if (( failed_count > 0 )); then
            printf '%s: %s check(s) failed; stopping\n' "$pr" "$failed_count" >&2
            return 1
        fi
        if (( check_count >= MIN_CHECKS && pending_count == 0 )); then
            printf '%s: checks passed (%s checks)\n' "$pr" "$check_count"
            return 0
        fi
        sleep 20
        elapsed=$((elapsed + 20))
    done
    printf '%s: checks did not complete within %s minutes\n' "$pr" "$MAX_WAIT_MINUTES" >&2
    return 1
}

for pr in "$@"; do
    printf '%s: updating branch\n' "$pr"
    old_oid="$(gh pr view "$pr" --json headRefOid --jq '.headRefOid')"
    if ! update_output="$(gh pr update-branch "$pr" 2>&1)"; then
        printf '%s: branch update failed: %s\n' "$pr" "$update_output" >&2
        exit 1
    fi
    if [[ -n "$update_output" ]]; then
        printf '%s: %s\n' "$pr" "$update_output"
    fi
    new_oid="$(gh pr view "$pr" --json headRefOid --jq '.headRefOid')"
    if [[ "$new_oid" != "$old_oid" ]]; then
        wait_for_head "$pr" "$old_oid"
    else
        printf '%s: head already current\n' "$pr"
    fi
    printf '%s: waiting for checks to register\n' "$pr"
    sleep 40
    wait_for_checks "$pr"
    merge_state="$(gh pr view "$pr" --json mergeStateStatus --jq '.mergeStateStatus')"
    if [[ "$merge_state" != "CLEAN" ]]; then
        failed_checks="$(gh pr checks "$pr" --json name,state --jq '.[] | select(.state == "FAILURE" or .state == "ERROR" or .state == "CANCELLED") | .name')"
        printf '%s: merge state %s; failed checks: %s\n' "$pr" "$merge_state" "${failed_checks:-none}" >&2
        exit 1
    fi
    gh pr merge "$pr" --squash
    merged_state="$(gh pr view "$pr" --json state --jq '.state')"
    if [[ "$merged_state" != "MERGED" ]]; then
        printf '%s: merge confirmation failed; state %s\n' "$pr" "$merged_state" >&2
        exit 1
    fi
    printf '%s: MERGED\n' "$pr"
done

printf 'ALL_DONE\n'
