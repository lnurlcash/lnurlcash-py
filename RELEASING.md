# Releasing lnurlcash-kit for Python

PyPI releases use OIDC trusted publishing. There is no PyPI token in GitHub or
on a maintainer's machine, and the publish job receives only distributions
that the build job has already tested and inspected.

## One-time setup

1. In this repository, create a `pypi` GitHub environment and restrict its
   deployment branches and tags to `v*.*.*`.
2. In PyPI's publishing settings, add a pending trusted publisher for:
   - PyPI project: `lnurlcash-kit`
   - GitHub owner: `lnurlcash`
   - Repository: `lnurlcash-py`
   - Workflow: `release.yml`
   - Environment: `pypi`

A pending publisher creates the project on the first successful publish; it
does not reserve the name beforehand.

## Rehearsal

Run the `release` workflow manually from `main` with the intended tag. The tag
is prospective and must not exist yet. This runs the full conformance suite,
builds the wheel and source archive, checks their metadata, and installs the
wheel into a clean environment. It never enters the publishing environment or
requests a publishing credential.

## Release

1. Keep `pyproject.toml` and `lnurlcash_kit.__version__` identical, and date
   the matching changelog entry.
2. Merge only after CI and the local distribution build pass.
3. Create and push the exact version tag, for example `v0.1.0`.
4. The tag validates the exact commit, then the protected `pypi` job publishes
   the already-built distributions through OIDC.
5. Verify the version, files, provenance and repository links on PyPI before
   creating the matching GitHub release.

Never reuse or move a published version tag.
