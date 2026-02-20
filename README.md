# Open Profile for DICE

This repository contains the specification for the
[Open Profile for DICE](docs/specification.md) along with production-quality
code. This profile is a specialization of the
[Hardware Requirements for a Device Identifier Composition Engine](https://trustedcomputinggroup.org/resource/hardware-requirements-for-a-device-identifier-composition-engine/)
and
[DICE Layering Architecture](https://trustedcomputinggroup.org/resource/dice-layering-architecture/)
specifications published by the Trusted Computing Group (TCG). For readers
already familiar with those specs, notable distinctives of this profile include:

*   Separate CDIs for attestation and sealing use cases
*   Categorized inputs, including values related to verified boot
*   Certified UDS values
*   X.509 or CBOR certificates

## Mailing List

You can find us (and join us!) at
https://groups.google.com/g/open-profile-for-dice. We're happy to answer
questions and discuss proposed changes or features.

## Specification

The specification can be found [here](docs/specification.md). It is versioned
using a major.minor scheme. Compatibility is maintained across minor versions
but not necessarily across major versions.

## Code

Production quality, portable C code is included. The main code is in
[dice.h](include/dice/dice.h) and [dice.c](src/dice.c). Cryptographic and
certificate generation operations are injected via a set of callbacks. Multiple
implementations of these operations are provided, all equally acceptable.
Integrators should choose just one of these, or write their own.

Tests are included for all code and the build files in this repository can be
used to build and run these tests.

Disclaimer: This is not an officially supported Google product.

### Thirdparty Dependencies

Different implementations use different third party libraries. The third\_party
directory contains build files and git submodules for each of these. The
submodules must be initialized once after cloning the repo, using `git submodule
update --init`, and updated after pulling commits that roll the submodules using
`git submodule update`.

### Building and Running Tests

#### Quick setup

To setup the build environment the first time:

```bash
$ git submodule update --init --recursive
$ source bootstrap.sh
$ gn gen out
```

To build and run tests:

```bash
$ ninja -C out
```

#### More details

The easiest way, and currently the only supported way, to build and run tests is
from a [Pigweed](https://pigweed.googlesource.com/pigweed/pigweed/) environment
on Linux. Pigweed does support other host platforms so it shouldn't be too hard
to get this running on Windows for example, but we use Linux.

There are two scripts to help set this up:

*   [bootstrap.sh](bootstrap.sh) will initialize submodules, bootstrap a Pigweed
    environment, and generate build files. This can take some time and may
    download on the order of 1GB of dependencies so the normal workflow is to
    just do this once.

*   [activate.sh](activate.sh) quickly reactivates an environment that has been
    previously bootstrapped.

These scripts must be sourced into the current session: `source activate.sh`.

In the environment, from the base directory of the dice-profile checkout, run
`ninja -C out` to build everything and run all tests. You can also run `pw
watch` which will build, run tests, and continue to watch for changes.

This will build and run tests on the host using the clang toolchain. Pigweed
makes it easy to configure other targets and toolchains. See
[toolchains/BUILD.gn](toolchains/BUILD.gn) and the Pigweed documentation.

### Porting

The code is designed to be portable and should work with a variety of modern
toolchains and in a variety of environments. The main code in dice.h and dice.c
is C99; it uses uint8\_t, size\_t, and memcpy from the C standard library. The
various ops implementations are as portable as their dependencies (often not C99
but still very portable). Notably, this code uses designated initializers for
readability. This is a feature available in C since C99 but missing from C++
until C++20 where it appears in a stricter form.

### Style

The [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html)
is used. A `.clang-format` file is provided for convenience.

### Incorporating

To incorporate the code into another project, there are a few options:

*   Copy only the necessary code. For example:

    1.  Take the main code as is: [include/dice/dice.h](include/dice/dice.h),
        [src/dice.c](src/dice.c)

    1.  Choose an implementation for crypto and certificate generation or choose
        to write your own. If you choose the boringssl implementation, for
        example, take [include/dice/utils.h](include/dice/utils.h),
        [include/dice/boringssl_ops.h](include/dice/boringssl_ops.h),
        [src/utils.c](src/utils.c), and
        [src/boringssl_ops.c](src/boringssl_ops.c). Taking a look at the library
        targets in BUILD.gn may be helpful.

*   Add this repository as a git submodule and integrate into the project build,
    optionally using the gn library targets provided.

*   Integrate into a project already using Pigweed using the gn build files
    provided.

### Size Reports

The build reports code size using
[Bloaty McBloatface](https://github.com/google/bloaty) via the pw\_bloat Pigweed
module. There are two reports generated:

*   Library sizes - This report includes just the library code in this
    repository. It shows the baseline DICE code with no ops selected, and it
    shows the delta introduced by choosing various ops implementations. This
    report **does not** include the size of the third party dependencies.

*   Executable sizes - This report includes sizes for the library code in this
    repository plus all dependencies linked into a simple main function which
    makes a single DICE call with all-zero input. It shows the baseline DICE
    code with no ops (and therefore no dependencies other than libc), and it
    shows the delta introduced by choosing various ops implementations. This
    report **does** include the size of the third party dependencies. Note that
    rows specialized from 'Boringssl Ops' use that as a baseline for sizing.

The reports will be in the build output, but you can also find the reports in
`.txt` files in the build output. For example, `cat out/host_optimized/gen/*.txt
| less` will display all reports.

### Thread Safety

This code does not itself use mutable global variables, or any other type of
shared data structure so there is no thread-safety concerns. However, additional
care is needed to ensure dependencies are configured to be thread-safe. For
example, the current boringssl configuration defines
OPENSSL\_NO\_THREADS\_CORRUPT\_MEMORY\_AND\_LEAK\_SECRETS\_IF\_THREADED, and
that would need to be changed before running in a threaded environment.

### Clearing Sensitive Data

This code makes a reasonable effort to clear memory holding sensitive data. This
may help with a broader strategy to clear sensitive data but it is not
sufficient on its own. Here are a few things to consider.

*   The caller of this code is responsible for buffers they own (of course).
*   The ops implementations need to clear any copies they make of sensitive
    data. Both boringssl and mbedtls attempt to zeroize but this may need
    additional care to integrate correctly. For example, boringssl skips
    optimization prevention when OPENSSL\_NO\_ASM is defined (and it is
    currently defined).
*   Sensitive data may remain in cache.
*   Sensitive data may have been swapped out.
*   Sensitive data may be included in a crash dump.
