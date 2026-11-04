# Working in microtasks

scadenza is built in small independent pieces. Each piece is a **microtask**:
one GitHub issue, one branch, one pull request. Many microtasks can run at the
same time, by people or by automated workers, because each one owns its own
files and carries its own complete brief.

This page is the method. [CONTRIBUTING.md](../CONTRIBUTING.md) has the rules
every pull request follows (DCO, required checks, protected `main`).

## Principles

1. **The issue is the brief.** Everything a worker needs is in the issue body:
   the goal, the files it may touch, and how to prove it is done. A brief that
   lives only in a chat or a scratch file is lost when the session ends; an
   issue is not.
2. **Small and independent.** A microtask is finished in under two hours and
   changes under 400 lines. If it cannot be, split it. It never needs another
   open microtask to be finished first; if it does, it is `status:blocked`.
3. **Disjoint files.** Two microtasks that run together must not edit the same
   file. The issue lists the files it owns, and the planner checks the lists
   before a wave starts.
4. **Verifiable.** Done is a list of commands and observable results, not an
   opinion. A test task proves each new test fails when the code it protects is
   broken.
5. **One pull request per issue, squash merged, closing the issue.** The pull
   request body says `Closes #N`, so merging closes the issue.
6. **Review by a different reader.** The change is reviewed by someone or
   something other than its author, and read-only reviews are tasks too.

## Anatomy of a microtask

Use the **Microtask** issue template. Its fields are:

| Field | What it holds |
| --- | --- |
| Goal | One or two sentences: the observable change. |
| Why | The finding, defect or promise it comes from, with a link. |
| Files you may change | The only paths the task edits. Anything else is out of scope. |
| Do not touch | Files that look related but belong to another task. |
| Done when | Commands that must pass and results that must be true. |
| Depends on | Issue numbers, or `none`. |
| Notes | Constraints, traps, and decisions already made. |

Labels carry the rest:

- `microtask`, plus one `size:` label (`size:xs` under 30 minutes and 50
  lines, `size:s` under an hour and 200 lines, `size:m` under two hours and 400
  lines).
- One `kind:` label (`test`, `fix`, `feat`, `docs`, `ci`, `perf`, `security`,
  `review`) and one or more `area:` labels.
- One `status:` label: `ready`, `in-progress`, `blocked` or `needs-decision`.
- `shared-files` when the task edits files that other tasks also edit, for
  example `CHANGELOG.md`, `docs/schema/*.json` or a generated page. Such a task
  runs alone.

Milestones group microtasks into **waves** (`wave-1`, `wave-2`, ...).

## Lifecycle

```text
backlog  ->  status:ready  ->  status:in-progress  ->  pull request  ->  merged and closed
                 |                                          |
                 +-> status:blocked / status:needs-decision +-> back to in-progress after review
```

1. **Ready.** The brief is complete and no dependency is open. Only ready
   issues are picked up.
2. **In progress.** The worker assigns the issue to themselves (or adds
   `status:in-progress`), creates the branch `mt/<number>-<slug>` from the
   current `main`, and works in its own worktree or clone.
3. **Pull request.** Open it early as a draft with `Closes #N` in the body. List
   what was verified and what was not.
4. **Merge.** When every required check is green, the pull request is squash
   merged and GitHub closes the issue.

### Closing issues

- **By pull request** (the normal way): `Closes #N` in the pull request body.
- **By hand**, when the outcome is not code: `gh issue close N --reason
  completed --comment "<what was found and where>"`, or `--reason "not
  planned"` with the reason when the task is dropped.
- A task that turns out to be too big is closed as `not planned` after it has
  been split into new microtasks that link back to it.
- Never close an issue whose acceptance commands were not run.

## Planning a wave

1. List the `status:ready` issues of the milestone.
2. Build the **ownership table**: one row per issue, with its files. Remove or
   reorder issues until no file appears twice. Put `shared-files` issues in their
   own wave step, alone.
3. Start at most **five to seven** microtasks at once. More than that makes the
   merge queue, not the work, the bottleneck.
4. Give every worker its issue number and nothing else: the brief is the issue.

## Merging in order

`main` requires a branch that is up to date, so pull requests merge one after
the other. After each merge the next branch is behind and its checks run again.
[`scripts/merge-queue.sh`](../scripts/merge-queue.sh) does this for a list of
pull requests: it updates the branch, waits for the checks, merges when the
state is clean, and stops at the first problem.

```sh
scripts/merge-queue.sh 61 62 63
```

When two pull requests edit the same hunk, the queue stops with a conflict.
Resolve it in the branch, keep both sides when both are right, and run it
again. If this happens often, the ownership table was wrong; fix the table.

## Roles

| Role | Does | Must not |
| --- | --- | --- |
| Planner | Writes issues, keeps the ownership table, sets the wave. | Start work that is not `ready`. |
| Worker | Does one microtask on its branch and opens the pull request. | Touch files outside the issue, or commit to `main`. |
| Reviewer | Reads the diff against the brief and runs the checks. A different reader than the worker. | Rewrite the change; ask for a fix instead. |
| Integrator | Runs the merge queue and resolves conflicts. | Merge a red or unreviewed pull request. |

One person can hold several roles. The rule that matters is that the reviewer
is not the author.

## Definition of ready

- The goal is one observable change.
- The files list is complete and does not overlap an open task.
- "Done when" has commands, and a test task says which change to the code the
  new test must catch.
- The expected values come from a documented promise (a doc, an ADR, a
  standard), not from "whatever the code returns now".
- Size is `xs`, `s` or `m`.

## Definition of done

- Every command in "Done when" was run and passed.
- `gofmt`, `go vet`, `go test ./...` and `golangci-lint run` pass; generated
  documentation is regenerated, never edited by hand.
- A test task shows each test failing against the matching broken change and
  passing against the real code. A change that finds a product defect stops and
  reports it instead of encoding the wrong behavior in a test.
- The pull request lists what was verified and what was not.
- Documentation that describes the changed behavior is updated in the same
  pull request.

## When a task goes wrong

- **It runs past two hours or stalls:** stop it, keep what compiles in the
  branch, and split the rest into new microtasks. The issue is the brief, so a
  new worker resumes from `git status` and the issue text without any other
  context.
- **It finds a bigger problem:** open a new issue for it; do not widen the
  current task.
- **A decision is needed:** set `status:needs-decision`, state the question and
  the options in the issue, and wait. Do not guess a product rule.
- **A review finds a defect in a merged change:** open a `kind:fix` microtask
  that links the pull request.
- **Two tasks need the same file:** run them one after the other. Do not merge
  conflicting work by guessing.

## Review tasks

A read-only review is a microtask with `kind:review`. Its brief names the area,
the questions, and a call budget. Its output is a list of concrete defects with
a file, a line and an input that triggers each one. Every finding becomes a new
microtask or a comment saying why it is not one; a review that only says
"looks fine" must say which questions it checked.
