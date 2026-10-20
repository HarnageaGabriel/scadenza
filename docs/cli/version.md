# `scadenza version`

`scadenza version` prints the build metadata of the binary: the version, the
commit it was built from, and the build date. It reads no configuration and no
network, and it exits 0.

```sh
scadenza version
```

```text
scadenza dev
commit: unknown
date: unknown
```

Options:

- `--json` prints the same information as one JSON object.

```sh
scadenza version --json
```

```json
{"version":"dev","commit":"unknown","date":"unknown"}
```

The three fields are `version`, `commit`, and `date`. A development build
reports `dev`, `unknown`, and `unknown`; a release build sets them with linker
flags, so a released binary reports the tag and the commit it was built from.
See the [release runbook](../release.md) for how a release is built and
verified.

## Shell completion

Cobra provides a `completion` command that writes the autocompletion script
for a shell to stdout:

```sh
scadenza completion bash
scadenza completion zsh
scadenza completion fish
scadenza completion powershell
```

- `bash` writes the script for bash. Load it in the current session with
  `source <(scadenza completion bash)`, or save it to
  `/etc/bash_completion.d/scadenza` for every new session. It needs the
  `bash-completion` package.
- `zsh` writes the script for zsh. Load it in the current session with
  `source <(scadenza completion zsh)`, or save it to `${fpath[1]}/_scadenza`.
  Shell completion has to be enabled first with `autoload -U compinit;
  compinit`.
- `fish` writes the script for fish. Load it in the current session with
  `scadenza completion fish | source`, or save it to
  `~/.config/fish/completions/scadenza.fish`.
- `powershell` writes the script for PowerShell. Load it in the current
  session with `scadenza completion powershell | Out-String |
  Invoke-Expression`, or add that line to the PowerShell profile.

Each of the four sub-commands also accepts `--no-descriptions`, which writes
the script without the completion descriptions.
