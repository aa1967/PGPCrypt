# Publishing Debian packages

The `.deb` is a GitHub **Release asset**, separate from the source checkout.
Unversioned builds also provide an artifact in [Actions](https://github.com/aa1967/PGPCrypt/actions).
Public downloads are in [Releases](https://github.com/aa1967/PGPCrypt/releases).

## Alpha5

The release workflow runs after a version tag is pushed. It uses Debian 13's
APT-provided compiler and Qt libraries, builds the package, runs checks on
GitHub, and attaches `pgpcrypt_0.1.0.alpha5_amd64.deb` plus `SHA256SUMS` to a
public prerelease. It needs no manually configured personal access token: only
the release job receives the repository's automatic `contents: write` token.
The SHA256 file detects corruption; it is not a publisher signature.

From a checkout with the alpha5 changes committed:

```sh
git push origin HEAD:refs/heads/pgpcrypt-alpha5
git tag v0.1.0-alpha5
git push origin refs/tags/v0.1.0-alpha5
```

There are no local test prerequisites or Git hooks. Checks run in Actions after
pushing. Watch the version-tag run; a failed build does not publish a package.
Repository Actions must be enabled and organization policy must permit the
release job's write permission. A pushed tag alone is not proof of a download.
If publication fails after building, rerun the failed release job. Do not move
or overwrite a published tag; issue a new version for changed source.

The workflow currently validates the explicit alpha5 tag. For the next release,
update that guard, package defaults, package paths, README and release notes in
the same source commit before tagging. Build artifacts and releases contain
compiled binaries, not a Rust installation requirement for end users.

GitHub prereleases appear on the Releases page; GitHub's `/releases/latest`
endpoint excludes them. Do not use it for this alpha download link.

## Source and merge

Open https://github.com/aa1967/PGPCrypt/compare/main...pgpcrypt-alpha5 to merge
the source change into main. The source branch and tag can build packages
without waiting for the merge. No GitHub Pages deployment is needed.
Never commit personal vaults, exported private keys, passphrases or credentials.
An APT repository with signed metadata and automatic updates is a separate step.

## Asset filenames

GitHub normalizes `~` in uploaded asset names to `.`. The package builder uses
a safe dotted filename before generating SHA256SUMS, while the package's internal
Debian Version stays `0.1.0~alpha5` for correct prerelease ordering. Install using
the actual downloaded filename. The Release checksums workflow can regenerate
SHA256SUMS from the `.deb` assets of an existing release without changing its
binaries or tag. It also repairs the initial alpha3 upload's checksum filenames.
