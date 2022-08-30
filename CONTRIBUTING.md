# Contributing to `sedire`

For more information on the `sedire` project and links to additional documentation, please see the project's [README](README.md).

## Canonical Repository

This project is maintained on Github with a canonical URL of:

    https://github.com/packetspace/sedire

Please ensure all contributions are targeted to the canonical repository.

## Questions / Discussion

This project utilizes the Github Discussions feature for general discussions as well as user support.  Any user may post in the `General` discussion category with ideas or comments for the project.  Users needing support and answers for specific questions should use the `Q&A` discussion category.

The Github Discussions system, along with the Github Issue Tracker noted below, are the exclusive official forums for project communication.

## Bug Reports / Feature Requests

All bug reports (including security vulnerabilities) and feature requests should be tracked as issues in the Github Issue Tracker for this project.  Please review existing issues (including searching for closed issues) before filing a new request.

If you are interested in contributing to the project and are looking for ideas for your efforts, please review open issues and add comments on those issues to which you would like to contribute.

## Versioning

SemVer is used for the versioning of this project.  Versions take the form of:

* _MAJOR_`.`_MINOR_`.`_PATCH_
* _MAJOR_`.`_MINOR_`-rc`_CANDIDATE_

All numbered versions (non-`rc`) are considered stable.  Changes in the major version number represent breaking changes for downstream users.  Changes in the minor version number represent non-breaking changes but could introduce new features or functionality.  Changes in the patch version number represent only bugfixes against that particular minor version.

Release candidate (`rc`) versions are considered unstable.  They occur prior to the first stable release of a minor version.  Once the first stable release of a minor version is issued (i.e. patch level 0), no more release candidates are created for that minor version.

All version number components are incremented independently using monotonically-increasing integers.  Major and release candidate version numbers start at 1, while minor and patch version numbers start at 0.

## Repository Structure

The Git repository for this project is organized according the structure documented herein.  All contributors should ensure that their work in the repository is consistent with this structure.

### Branches

The following branch namespaces are defined:

* `main`

    The main (trunk) branch of the project.  Commits are not made directly against this branch, instead they are merged into this branch via pull requests from issue or feature branches.

* `issue/`_ISSUE NUMBER_

    A short-lived branch for changes tied to a specific issue, such as a feature request or a bug.  Branches should be created in this namespace as needed for issues and then deleted once merged to the `main` branch.

    **Example:** `issue/285`

* `feature/`_FEATURE NAME_

    A medium-lived branch for complex features, such as features that span multiple issues or project-maintainer initiatives that don't correspond directly to any issue.  Branches should be created in this namespace as needed for features being developed or improved and then deleted once merged into the `main` branch.  No standard is defined herein for the _FEATURE NAME_ but a reasonable short textual name should be selected, with hyphens (`-`) used as word separators as needed.

    **Example:** `feature/external-logging-support`

* `release/`_MAJOR_`.`_MINOR_

    A long-lived branch for each release train of the project.  These branches are created for every minor release by the release manager.  Commits are not made directly against this branch, instead bugfix changes are cherry-picked into these branches as needed, prior to an initial or patch release.  All version tags point to a release branch.

    **Example:** `release/1.3`

### Tags

The following tag namespaces are defined:

* `v`_MAJOR_`.`_MINOR_`.`_PATCH_

    A published release of the software.  All releases tagged in this manner should be considered stable and available as build targets.

    **Example:** `v1.3.0` (against a version in the `release/1.3` branch)

* `v`_MAJOR_`.`_MINOR_`-rc`_CANDIDATE_

    A pre-release candidate of the software.  All releases tagged in this manner should be considered unstable and but are available as build targets for testing prior to the first patch release (`.0`) of the given minor version.

    **Example:** `v1.3-rc1` (against a version in the `release/1.3` branch)

## Changes

Aside from the initial project establishment and certain limited project administrative changes, no commits should be directly made against the `main` or release branches.  Instead, all commits should be made against one of the issue or feature branches.  Then, a pull request should be used to merge those changes to the appropriate branch.

Contributors and maintainers can create new branches in the `issue/` or `feature/` trees as needed for pending work.  Third-party contributions may be made in user forks of the project and proposed for pulling by a contributor or maintainer using a Github issue.  Alternatively, third-party users intending to spend time on a given issue or feature can be granted limited contributor access by a maintainer for that purpose, if requested in a Github issue.

See the [Github documentation for pull requests](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request) for more information.