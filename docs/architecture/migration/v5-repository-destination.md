# CLAASP 5 repository destination authority

This record captures the release-preservation policy before any external
repository is created or transferred. The machine authority is
`next/migration/m11_repository_destination.json`; the closure gate is
`next/tools/repository_destination_closure.py --check`.

## Current facts

The source repository is the public `Crypto-TII/claasp` repository. On
2026-09-20 it had 79 stars, 14 forks, five subscribers, and ten releases. The
preferred GitHub handle `claasp` was occupied by a personal account created in
2019, so it could not be created as an organization. No alternate organization
name has been accepted and no destination organization or staging repository
has been created by this work.

The inventory records eight candidate repositories whose names contain
CLAASP. It is a discovery set, not authorization to transfer them: project
owners must confirm the set, target names, and visibility before migration.

## Preservation procedure

The existing `Crypto-TII/claasp` repository must stay public during private
release preparation. GitHub documents that changing a public repository to
private removes stars and watchers and detaches public forks. Private staging
therefore uses a distinct temporary name. Once the complete release candidate
passes, the existing public repository is transferred to the accepted
organization without a visibility change, preserving its GitHub identity and
redirects, and the validated v5 branch is then installed as the default. A v4
maintenance tag or branch remains available.

Before external creation or transfer, the project owners must resolve the
preferred handle or approve another one, name at least two organization
owners, verify source and destination permissions, and approve the affiliated
repository inventory. The publication step remains intentionally separate
from private staging.

## Authoritative platform references

- [Transferring a repository](https://docs.github.com/en/repositories/creating-and-managing-repositories/transferring-a-repository)
- [Setting repository visibility](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/setting-repository-visibility)
