# Publishing Debian packages

The `.deb` is a GitHub **Release asset**, separate from the source checkout.
Unversioned builds also provide an artifact in [Actions](https://github.com/aa1967/PGPCrypt/actions).
Public downloads are in [Releases](https://github.com/aa1967/PGPCrypt/releases).

## Alpha3

The release workflow runs after a version tag is pushed. It uses Debian 13's
APT-provided compiler and Qt libraries, builds the package, runs checks on
GitHub, and attaches `pgpcrypt_0.1.0~alpha3_amd64.deb` plus `SHA256SUMS` to a
public prerelease. It needs no manually configured personal access token: only
the release job receives the repository's automatic `contents: write` token.
The SHA256 file detects corruption; it is not a publisher signature.

From a checkout with the alpha3 changes committed:

```sh
git push origin HEAD:refs/heads/pgpcrypt-alpha3
git tag v0.1.0-alpha3
git push origin refs/tags/v0.1.0-alpha3
```

There are no local test prerequisites or Git hooks. Checks run in Actions after
pushing. Watch the version-tag run; a failed build does not publish a package.
Repository Actions must be enabled and organization policy must permit the
release job's write permission. A pushed tag alone is not proof of a download.
If publication fails after building, rerun the failed release job. Do not move
or overwrite a published tag; issue a new version for changed source.

The workflow currently validates the explicit alpha3 tag. For the next release,
update that guard, package defaults, package paths, README and release notes in
the same source commit before tagging. Build artifacts and releases contain
compiled binaries, not a Rust installation requirement for end users.

GitHub prereleases appear on the Releases page; GitHub's `/releases/latest`
endpoint excludes them. Do not use it for this alpha download link.

## Source and merge

Open https://github.com/aa1967/PGPCrypt/compare/main...pgpcrypt-alpha3 to merge
the source change into main. The source branch and tag can build packages
without waiting for the merge. No GitHub Pages deployment is needed.
Never commit personal vaults, exported private keys, passphrases or credentials.
An APT repository with signed metadata and automatic updates is a separate step.
