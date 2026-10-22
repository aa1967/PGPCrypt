# Viewing and publishing the project on GitHub

## What appears where

- https://github.com/aa1967/PGPCrypt — source and README on the selected branch.
- https://github.com/aa1967/PGPCrypt/actions — workflow logs and downloadable build artifacts.
- https://github.com/aa1967/PGPCrypt/releases — releases and attached packages after publication.

A desktop app runs on Debian, not inside GitHub Pages. The README screenshot
provides a preview; download/install the package to use the interface.

Publishing a Codex cloud environment saves its development configuration and
snapshot. It does **not** commit, push or publish this repository. Local edited
and untracked files remain absent from public GitHub until pushed.

During this work a read-only `git ls-remote --heads origin` check showed public
`main` at initial commit `32f52e2710c642a22f30fc4398bc721b52050cfa` (README only).
No code push or GitHub Release was performed by the assistant.

## Publish source from the prepared checkout

Review changes first, including the new files. From this checkout, using your
normal GitHub Git authentication and configured Git author identity:

```sh
git status --short
git switch -c pgpcrypt-alpha2
git add README.md .gitignore Cargo.toml Cargo.lock rust-toolchain.toml \
  src desktop scripts tests packaging docs .github
git commit -m "Add Qt6 desktop, standard age vaults and Debian packaging"
git push -u origin pgpcrypt-alpha2
```

Then view https://github.com/aa1967/PGPCrypt/tree/pgpcrypt-alpha2.
Open https://github.com/aa1967/PGPCrypt/compare/main...pgpcrypt-alpha2 to propose
merging it into `main`. The default Code page changes only after selecting that
branch or merging the change. Do not force-push to work around a rejected push.
Never commit personal vault files, key exports or credentials. The included
legacy migration fixture is explicitly disposable test data with a public test
passphrase, not a user's vault.

## Build artifacts and binary releases

The checked-in Debian workflow builds/tests on Debian 13 with package-managed
Rust. It can run on main, pull requests, or manually through Actions. A successful
run provides the `pgpcrypt-debian13-amd64` artifact. Unzip it to obtain `.deb` and
SHA256SUMS. The workflow does not create public releases automatically.

To make a stable download location, a maintainer can create a prerelease in
GitHub Releases and attach the tested `.deb` and SHA256SUMS. Choose an application
license and complete dependency/release review before public binary distribution.
An APT repository with signed metadata and automatic updates is a separate step.
