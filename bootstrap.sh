# Copyright 2020 Google LLC
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

# Sets up an environment ready to build and run tests. For example, 'pw watch'
# should work in this environment.
#
# Usage: source bootstrap.sh

# Update submodules, initializing if necessary. This will pin all submodules to
# the committed revision so don't run this with uncommitted changes in a
# submodule. By convention, submodules are pinned to an upstream revision and
# any changes should be submitted upstream. Local changes to submodules are not
# carried long term, but patches waiting to land upstream may be applied
# manually.
git submodule update --init

# Bootstrap the pigweed environment.
. third_party/pigweed/src/bootstrap.sh

# Copy the pigweed environment config with a path fixup.
sed s/environment/third_party\\\/pigweed\\\/src\\\/environment/g \
  < third_party/pigweed/src/build_overrides/pigweed_environment.gni \
  > build_overrides/pigweed_environment.gni
gn format build_overrides/pigweed_environment.gni

# Setup the build.
gn gen --export-compile-commands out
