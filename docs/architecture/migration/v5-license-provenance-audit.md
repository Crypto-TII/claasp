# CLAASP 5 license-provenance audit

This is an engineering provenance audit, not legal advice. Its machine
authority is `next/migration/m11_license_provenance.json`, enforced by
`next/tools/license_provenance_closure.py --check`. The gate covers every
tracked artifact shipped from `next/src/claasp_next` and prevents package
metadata from changing while legal approval is pending.

## Decision

CLAASP 5 remains `GPL-3.0-or-later`. Removing SageMath is architecturally
important, but it does not change copyright ownership or the license of code
copied or adapted from the GPL-licensed CLAASP history. Neither MIT nor
Apache-2.0 can be selected merely because the former dependency disappeared.

The repository introduced GPLv3 in commit
`8fb88c5e254482012e5158136d941d3e78262686`; the initial code followed in
`f2c8ca4c0cc9cd2989cae4c4ecb49c8872784f3a`. No contributor license agreement
or developer certificate of origin is committed. At the audit date, the
legacy source/test/documentation history contained 57 normalized Git author
identities and GitHub reported 30 contributor accounts. GitHub's default
inbound term licenses contributions under the repository's license; it is not
a blanket grant to relicense them.

Apache-2.0 code may be combined into a GPLv3 work, but that compatibility does
not make the resulting GPL-covered work available under Apache-2.0. MIT has
the same underlying ownership problem here: a permissive outbound license
requires authority from every relevant copyright holder.

## Shipped-artifact findings

The v5 package contains 408 tracked artifacts: 394 Python files, eleven LowMC
parameter files, two JSON data files, and one third-party notice. Python code
is new or migrated CLAASP work and remains under the current project license
pending rights evidence. The LowMC files came from the legacy GPL tree, but
their upstream provenance is not recorded; that is a specific relicensing
blocker. The generated catalogue remains project material.

The Poseidon BN254 parameters derive from `ingonyama-zk/poseidon-hash` commit
`5194eadce26b3fe4b1c4fe2a5ca9f6436f3b0e3d`. Its MIT notice is present beside
the data and must remain in every distribution regardless of the project-wide
decision.

## Evidence needed for a permissive license

TII legal counsel must identify every copyright interest and confirm the
applicable employee, contractor, and contributor assignments or obtain
explicit relicensing grants. It must resolve the LowMC data provenance,
preserve the Poseidon notice, and approve the exact SPDX license in writing.
Alternatively, material without permission must be independently replaced
with documented clean provenance. Only then may the manifest status, root
license, and package metadata change together.

## Authoritative references

- [GitHub Terms of Service: contributions under repository license](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service)
- [GNU GPL FAQ](https://www.gnu.org/licenses/gpl-faq.en.html)
- [Apache Software Foundation GPL compatibility](https://www.apache.org/licenses/GPL-compatibility)
- [Open Source Initiative FAQ on contributor agreements](https://opensource.org/faq)
