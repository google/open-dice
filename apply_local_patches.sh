#!/bin/sh

# Copyright 2026 Google LLC
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

# This script needs to be executed after third party source code is synced.

set -eu

THIRD_PARTY_ROOT="$(pwd)/third_party"

# Add new patched projects here with a space. Eg: "cose-c boringssl"
PATCHED_PROJECTS="cose-c"

for project in $PATCHED_PROJECTS; do
  PROJECT_ROOT="$THIRD_PARTY_ROOT/$project"
  PROJECT_SRC="$PROJECT_ROOT/src"
  PATCHES_FOLDER="$PROJECT_ROOT/patches"

  # Double-check that the submodule has been checked out.
  if [ "$(find "$PROJECT_SRC/." -print | head -n 2 | wc -l)" -le 1 ]; then
    echo "Error: $PROJECT_SRC is empty."
    echo "Did you forget to initialize the git submodules?"
    echo "To setup the git submodules run:"
    echo "  git submodule update --init --recursive"
    exit 1
  fi

  if [ -d "$PATCHES_FOLDER" ] && \
       [ "$(find "$PATCHES_FOLDER/." -print | head -n 2 | wc -l)" -gt 1 ]; then
    echo "Applying patches from $project"
    git -C "$PROJECT_SRC" am "$PATCHES_FOLDER"/*
  else
    echo "No patches to apply for $project"
  fi
done

echo "Patching complete."
