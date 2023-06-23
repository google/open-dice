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
#
# Lint as: python3
"""Generates known_test_values.h from dumped test values.

This program generates the known_test_values.h file used for unit tests. This is
useful to correct the baseline test values based on dumps from the tests. Use
this after fixing a bug in the code, not to 'fix' test breakage not well
understood.

Usage:
  $ cd out
  $ python ../generate_test_values.py > ../include/dice/known_test_values.h

Prerequisites:
  pip install absl-py
"""

from __future__ import print_function

import re
import subprocess
import textwrap

from absl import app
from absl import flags

FLAGS = flags.FLAGS

_FILE_HEADER = textwrap.dedent(
    """\
    // Copyright 2020 Google LLC
    //
    // Licensed under the Apache License, Version 2.0 (the "License"); you may not
    // use this file except in compliance with the License. You may obtain a copy of
    // the License at
    //
    //     https://www.apache.org/licenses/LICENSE-2.0
    //
    // Unless required by applicable law or agreed to in writing, software
    // distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
    // WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
    // License for the specific language governing permissions and limitations under
    // the License.

    // !!! GENERATED - DO NOT MODIFY !!!
    // To update this file, use generate_test_values.py.

    #ifndef DICE_KNOWN_TEST_VALUES_H_
    #define DICE_KNOWN_TEST_VALUES_H_

    #include <stdint.h>

    namespace dice {
    namespace test {

                               """
)

_FILE_FOOTER = textwrap.dedent(
    """\
    }  // namespace test
    }  // namespace dice

    #endif  // DICE_KNOWN_TEST_VALUES_H_
                               """
)


def _to_camel_case(s):
    return "".join(tmp.capitalize() for tmp in s.split("_"))


def _read_file(name):
    try:
        with open(name, "rb") as f:
            return f.read()
    except OSError:
        return ""


def _generate_array(name, data):
    return "constexpr uint8_t %s[%d] = {%s};\n\n" % (
        name,
        len(data),
        ", ".join("0x%02x" % tmp for tmp in data),
    )


def _generate_cert_comment(data):
    return re.sub(
        "^",
        "// ",
        subprocess.run(
            [
                "openssl",
                "x509",
                "-inform",
                "DER",
                "-noout",
                "-text",
                "-certopt",
                "ext_parse",
            ],
            input=data,
            capture_output=True,
            check=True,
        ).stdout.decode(),
        flags=re.MULTILINE,
    )[:-3]


def _generate_c(name):
    """Generates C declarations from dumps identified by |name|."""
    content = ""
    attest_cdi_data = _read_file("_attest_cdi_%s.bin" % name)
    content += _generate_array(
        "kExpectedCdiAttest_%s" % _to_camel_case(name), attest_cdi_data
    )
    seal_cdi_data = _read_file("_seal_cdi_%s.bin" % name)
    content += _generate_array(
        "kExpectedCdiSeal_%s" % _to_camel_case(name), seal_cdi_data
    )
    for cert_type in ("X509", "CBOR"):
        for key_type in ("Ed25519", "P256", "P384"):
            var_name = "kExpected%s%sCert_%s" % (
                _to_camel_case(cert_type),
                _to_camel_case(key_type),
                _to_camel_case(name),
            )
            cert_data = _read_file(
                "_%s_%s_cert_%s.cert" % (cert_type, key_type, name)
            )
            if cert_type == "X509" and key_type != "P384":
                content += (
                    "// $ openssl x509 -inform DER -noout -text -certopt "
                    "ext_parse\n"
                )
                content += _generate_cert_comment(cert_data)
            content += _generate_array(var_name, cert_data)
    return content


def main(argv):
    if len(argv) > 1:
        raise app.UsageError("Too many command-line arguments.")

    content = _FILE_HEADER
    content += _generate_c("zero_input")
    content += _generate_c("hash_only_input")
    content += _generate_c("descriptor_input")
    content += _FILE_FOOTER
    subprocess.run(
        ["clang-format", "--style=file"], input=content.encode(), check=True
    )


if __name__ == "__main__":
    app.run(main)
