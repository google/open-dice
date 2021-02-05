#!/bin/bash
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
readonly FUZZER_DIR="./out/host_fuzz/obj/bin"

if [[ $# -eq 0 ]]; then
  echo "Usage: ${0} FUZZER"
  echo "Available fuzzers:"
  ls ${FUZZER_DIR} -1 | grep 'fuzzer$' | sed 's/^/  - /'
  exit
fi

readonly ARTIFACTS_DIR="fuzzer_data/${1}_artifacts"
readonly CORPUS_DIR="fuzzer_data/${1}_corpus"

mkdir -p "${ARTIFACTS_DIR}"
mkdir -p "${CORPUS_DIR}"

"${FUZZER_DIR}/${1}" -artifact_prefix="${ARTIFACTS_DIR}/" -timeout=10 "${CORPUS_DIR}"
