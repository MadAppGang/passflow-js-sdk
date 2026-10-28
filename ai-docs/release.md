# Release playbook — passflow-js-sdk (`@passflow/core`)

Authored 2026-10-28 by `/dev:release` in autonomous mode. No interview was run; every
line below is what detection could read out of the repo, and anything it could not read
is marked `unknown` with what would settle it.

## Authority

- `.github/workflows/publish.yml` — owns publishing. It is the ONLY publisher; nothing
  publishes from a developer machine.
- `.github/workflows/node.js.yml` — owns the pre-merge gate (lint, test, build) on
  pushes to `main` and on PRs into it.
- `package.json` — owns the version, the entry points and the published file set.
- `CLAUDE.md` — says nothing about releasing. Checked; it is not an authority here.

There is no RELEASE.md, no CONTRIBUTING.md, and no release tooling (no changesets, no
release-please, no semantic-release, no standard-version). The CI workflow is the whole
of the machinery.

## Artifacts

One npm package, `@passflow/core`, to registry.npmjs.org, public, with npm provenance
signed by GitHub Actions OIDC. `package.json`'s `files` field decides what ships;
`exports` decides what is importable. "Released" means: the tag is on origin, the
workflow concluded success, and the registry serves the version.

## Stages

`none`. One publish job on one trigger, straight to the public registry. There is no
prerelease channel, no dist-tag other than `latest`, and no environment gating in either
workflow.

## Dependencies

1. **Lockfile in sync** — `pnpm install --frozen-lockfile` proves it. Note that
   `publish.yml` itself runs a bare `pnpm install`, which will happily resolve a
   drifted lockfile rather than fail; the frozen check therefore has to happen in
   preflight, not in CI.
2. **Internal lockstep** — none. Single package, no workspace, no
   `optionalDependencies`, no platform packages.
3. **External prerequisites** — none blocking. `passflow-react-sdk` consumes this
   package and must be released after it when a change is breaking, but this package's
   release never waits on that one.

## CI/CD

`publish.yml`, triggered on `push` of a tag matching `v*`. Two jobs: `publish`
installs, runs `pnpm test`, builds, then `npm publish --provenance --access public`
with `id-token: write` and `NODE_AUTH_TOKEN: ''` — the empty token is deliberate; auth
is OIDC trusted publishing, so no npm secret exists and a local npm login is
irrelevant. `release-page` then `needs: publish` and creates the GitHub release.

The split is on purpose and should survive a tidy-up: it keeps `contents: write` out
of the job that runs `pnpm install`, `pnpm test` and `pnpm build`, i.e. third-party
code, and that job takes no checkout so the write token never reaches a working tree.

**The soft-fail shape specific to this project**: as of v0.17.0 the workflow asserts
that the tag matches `package.json`'s version ("Verify tag matches package version",
ported from `passflow-react-sdk`), so the old shape — a tag pushed at a commit whose
manifest says something else, publishing the MANIFEST's version and concluding green —
now fails the run instead. The guard was added because the release page made that shape
worse: a mismatch would have produced a durable page asserting a version that was never
published, aimed at exactly the readers who cannot check npm.

Still read the publish step's own confirmation line rather than the run conclusion,
because the guard proves tag/manifest agreement, not that a publish happened:

    gh run view <id> --log | grep -E '^\+ @passflow/core@'

That line names the version actually published.

`release-page` is idempotent (`gh release view ... || gh release create ...`), so a
re-run does not fail on "release already exists". A release created with
`secrets.GITHUB_TOKEN` does NOT fire `release: published`, so nothing may be keyed on
that event.

There are no `if:` conditions, no `continue-on-error`, and no guard job that can
decide "nothing to publish", so a skipped job is not a shape this project produces.

**Known drift from the sibling repo**, deliberately not reconciled during a release:
`actions/checkout@v4` vs react-sdk's `@v7`, Node 24 vs 22, and `pnpm install` vs
`--frozen-lockfile`. The last one matters most — without the flag the resolved
dependency set can drift at publish time.

## Deploy monitoring

`none`. This repo publishes a library; it deploys no service and exposes no health
endpoint. There is nothing to watch after the registry serves the version.

## Verification

- `git ls-remote --tags origin refs/tags/vX.Y.Z` — exactly one ref, at the merge SHA.
- The publish run concluded success AND its log carries `+ @passflow/core@X.Y.Z`.
- `https://registry.npmjs.org/@passflow/core/X.Y.Z` returns 200. Query the registry
  directly rather than through `npm view`: npm's local metadata cache served a stale
  `0.14.1` for several minutes after 0.15.0 published.
- `dist-tags.latest` has moved to the new version. Observed propagation for 0.15.0 was
  roughly nine minutes between the workflow reporting success and the single-version
  endpoint answering 200, with `latest` flipping after that. An early 404 is lag, not
  failure; poll.

## Rollback

- **Pushed tag** — immutable in practice. Never delete, never retarget. Forward fix.
- **Registry version** — immutable; npm does not allow republishing a version. Mask then
  fix forward: `npm dist-tag add @passflow/core@<last-good> latest` to stop new
  installs picking it up, `npm deprecate @passflow/core@X.Y.Z "<reason>"` for a durable
  warning, then release the next version. Do not unpublish; it breaks dependents and npm
  constrains it to a 72-hour window anyway.
- **Pre-tag state** — fully reversible. Reset the branch or close the PR.

## Decisions

`unknown` — who may authorise a release of this package in general is not recorded
anywhere in the repo. For the 0.16.0 run the repository owner authorised it explicitly in
session. TODO: record the standing rule (owner only? any maintainer? does a breaking
change need a second pair of eyes?).

What the release command may do without asking, as exercised on 0.16.0: open the release
PR, merge it once CI is green, push the tag, and let the workflow publish — reporting each
irreversible step as it happens rather than pausing for it.

## Known gaps in this file

- This playbook is tracked. `.gitignore` ignored all of `ai-docs/` until 2026-10-28, which
  made it machine-local; the ignore is now narrowed to `ai-docs/sessions/`, so the
  per-session scratch stays out of history and the durable notes do not.
- `Decisions` is `unknown`, as above.

verified: 2026-10-28 @ c7b698d
