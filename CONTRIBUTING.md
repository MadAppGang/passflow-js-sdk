# Contributing

## Tooling

- pnpm 12, pinned by `packageManager` in `package.json`. With Corepack or a recent pnpm
  installed, running `pnpm` in this repo uses that version.
- `pnpm install`, `pnpm lint`, `pnpm test`, `pnpm build` and `pnpm check:types-consumer`
  are the checks CI runs. The last one packs the build and type-checks it as a consumer
  would, under node16, nodenext, bundler and node16 CommonJS.

## Dependency age policy

`pnpm-workspace.yaml` sets a supply-chain age gate:

```yaml
minimumReleaseAge: 4320 # minutes, i.e. 3 days
minimumReleaseAgeStrict: true
minimumReleaseAgeExclude:
  - '@passflow/*'
```

pnpm will not resolve a version that has been on the registry for less than 3 days, and
every install, frozen CI installs included, re-checks the versions already in
`pnpm-lock.yaml` against the same rule.

### Why 3 days

The npm compromises this gate defends against were usually pulled within hours, but a
publish late on a Friday is often only flagged on Monday. Three days covers a weekend of
detection lag. pnpm's built-in default is 1 day. A week would turn every dependency bump in
this repo, which upgrades often, into a week-long wait or a growing exclusion list.

The setting is explicit, so it is strict: a violation fails the install instead of pnpm
quietly adding exclusions to `pnpm-workspace.yaml`.

### Adding a third-party package younger than 3 days

Don't. Wait until it is 3 days old.

Only for an urgent security fix: add the exact version, `name@x.y.z`, to
`minimumReleaseAgeExclude` in the same commit as the upgrade, with a comment naming the
advisory. Remove the entry once that version is older than 3 days. Order matters when you
remove it: if the lockfile still holds a version younger than 3 days, run
`pnpm update <name>` first, then delete the exclusion, or the next install fails on the
version that is still locked.

### First-party `@passflow/*` packages

`@passflow/*` is excluded by pattern. We publish those packages ourselves, only through our
own `publish.yml` with npm OIDC trusted publishing and provenance, and a fresh Passflow
release must be consumable at once (for example, a core fix another Passflow package needs
the same day). No `@passflow/*` dependency exists in this repo today; the rule is kept so
every Passflow repo carries the same policy.

The trade-off: if the npm org or the OIDC trust were compromised, a malicious `@passflow/*`
version would be taken at once. If the org wants it narrower, replace the pattern with one
`@passflow/<package>@<version>` entry per release, and remove each entry once it is 3 days
old.

### When CI fails with `ERR_PNPM_MINIMUM_RELEASE_AGE_VIOLATION`

The lockfile holds a version younger than 3 days. Run `pnpm update <listed packages>`, which
resolves the newest version that passes the gate, and commit the updated `pnpm-lock.yaml`.

### Settings are checked

pnpm 12 rejects unknown keys in `pnpm-workspace.yaml` with
`ERR_PNPM_UNRECOGNIZED_WORKSPACE_SETTINGS` and suggests the nearest name, so a misspelled
setting fails the install instead of being ignored.
