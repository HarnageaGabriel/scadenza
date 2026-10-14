# Scheduled GitHub Actions CI

This example runs the strict scan policy on a schedule and preserves output
even when the command fails:

```yaml
name: scadenza scheduled scan
on:
  schedule: [{cron: '0 6 * * 1'}]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with: {go-version: stable}
      # Pin a commit until a tagged release exists.
      - run: go install github.com/HarnageaGabriel/scadenza/cmd/scadenza@main
      - name: Scan
        env:
          SCADENZA_CERTSPOTTER_KEY: ${{ secrets.SCADENZA_CERTSPOTTER_KEY }}  # optional
        run: |
          scadenza scan --domain example.com --format json \
            --fail-on live_only,not-compliant-at-issuance \
            --min-coverage 90 --strict > scadenza.json
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        if: always()
        with: {name: scadenza-results, path: scadenza.json, if-no-files-found: ignore}
```

Replace `example.com` with your domain. Once a release exists, install a pinned
version instead of `@main`. The Cert Spotter key is optional; without it the
unauthenticated quota applies.

| Exit code | Meaning |
| ---: | --- |
| 0 | Clean result; see [exit codes](../exit-codes.md#exit-codes). |
| 1 | Internal error; see [exit codes](../exit-codes.md#exit-codes). |
| 2 | Invalid input; see [exit codes](../exit-codes.md#exit-codes). |
| 3 | Selected finding; see [exit codes](../exit-codes.md#exit-codes). |
| 4 | All requested sources unavailable; see [exit codes](../exit-codes.md#exit-codes). |
| 5 | Incomplete scan; see [exit codes](../exit-codes.md#exit-codes). |
