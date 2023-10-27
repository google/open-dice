# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
"""Presubmit script."""

import argparse
import logging
import os
from pathlib import Path
import re
import sys

import pw_cli.log
import pw_presubmit
from pw_presubmit import (
    build,
    cli,
    cpp_checks,
    format_code,
    git_repo,
    inclusive_language,
    install_hook,
    keep_sorted,
    presubmit_context,
    python_checks,
)

_LOG = logging.getLogger(__name__)

# Set up variables for key project paths.
try:
    PROJECT_ROOT = Path(os.environ["PW_PROJECT_ROOT"])
except KeyError:
    print(
        "ERROR: The presubmit checks must be run in the Open Dice project's "
        "root directory",
        file=sys.stderr,
    )
    sys.exit(2)

PIGWEED_ROOT = PROJECT_ROOT / "third_party" / "pigweed" / "src"

# Rerun the build if files with these extensions change.
_BUILD_EXTENSIONS = frozenset(
    [".rst", ".gn", ".gni", *format_code.C_FORMAT.extensions]
)

default_build = build.GnGenNinja(name="default_build")

EXCLUSIONS = presubmit_context.FormatOptions.load().exclude

OTHER_CHECKS = (build.gn_gen_check,)

_FORMAT = (format_code.presubmit_checks(exclude=EXCLUSIONS),)

QUICK = (
    default_build,
    _FORMAT,
)


def include_guard(path: Path) -> str:
    path = path.relative_to(PROJECT_ROOT)
    exclude = ("include",)
    transform = {"ulib": "lib"}
    parts = [transform.get(x, x) for x in path.parts if x not in exclude]
    return re.sub(r"[.-]", "_", "".join(f"{x}_" for x in parts).upper())


LINTFORMAT = (
    _FORMAT,
    cpp_checks.include_guard_check(include_guard).with_filter(
        exclude=EXCLUSIONS
    ),
    inclusive_language.presubmit_check.with_filter(exclude=EXCLUSIONS),
    keep_sorted.presubmit_check.with_filter(exclude=EXCLUSIONS),
    python_checks.gn_python_lint,
)

FULL = (
    QUICK,  # Add all checks from the 'quick' program
    LINTFORMAT,
    # Use the upstream Python checks, with custom path filters applied.
    python_checks.gn_python_check,
)

PROGRAMS = pw_presubmit.Programs(
    # keep-sorted: start
    full=FULL,
    lintformat=LINTFORMAT,
    other_checks=OTHER_CHECKS,
    quick=QUICK,
    # keep-sorted: end
)


def run(install: bool, exclude: list, **presubmit_args) -> int:
    """Process the --install argument then invoke pw_presubmit."""

    # Install the presubmit Git pre-push hook, if requested.
    if install:
        install_hook.install_git_hook(
            "pre-push",
            [
                "python",
                "-m",
                "open_dice_tools.presubmit",
                "--base",
                "origin/main..HEAD",
                "--program",
                "quick",
            ],
        )
        return 0

    repos = git_repo.discover_submodules(superproject_dir=PROJECT_ROOT)
    return cli.run(
        root=PROJECT_ROOT, repositories=repos, exclude=exclude, **presubmit_args
    )


def main() -> int:
    """Run the presubmit checks for this repository."""
    parser = argparse.ArgumentParser(description=__doc__)
    cli.add_arguments(parser, PROGRAMS, "quick")

    # Define an option for installing a Git pre-push hook for this script.
    parser.add_argument(
        "--install",
        action="store_true",
        help="Install the presubmit as a Git pre-push hook and exit.",
    )

    return run(**vars(parser.parse_args()))


if __name__ == "__main__":
    pw_cli.log.install(logging.INFO)
    sys.exit(main())
