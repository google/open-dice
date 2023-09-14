# Android Profile for DICE

[TOC]

## Background

The Android Profile for DICE is a specialization of the [Open Profile for
DICE](specification.md) that provides additional detail around algorithms,
certificates, and configuration descriptor. The choices are made to meet the
needs of the Android ecosystem.

This profile is not always a strict refinement of the Open Profile for DICE as
it also forced to address practical concerns such as workarounds for errata in
ROMs that require a relaxation of the base specification. However, the objective
is to avoid these where practical.

## Cryptographic Algorithms

The choice of algorithm must remain consistent with any given certificate e.g.
if SHA-256 is the hash algorithm used for the code hash then the authority hash,
config hash, etc. must also use SHA-256.

See the Open Profile for DICE's [acceptable cryptographic
algorithms](specification.md#acceptable-cryptographic-algorithms) for more
detail on specific algorithms.

### Hash Algorithms

Acceptable hash algorithms are:

*   SHA-256, SHA-384, SHA-512

Unlike the Open Profile for DICE, digests can be used as DICE inputs at their
output size without needing to be resized to 64 bytes. The value that is used as
the DICE input must be listed in the certificate. E.g. SHA-256 digests can be
used as 32-byte DICE inputs with the same 32 bytes encoded as a byte string in
the certificate.

### Key Derivation Functions

HKDF with a [supported hash algorithm](#hash-algorithms), or
[CKDF](https://datatracker.ietf.org/doc/html/draft-agl-ckdf-00) for all key
derivation.

### Digital Signatures

Ed25519 is recommended for performance and memory usage reasons. ECDSA with
curves P-256 or P-384 are acceptable.

## Certificate Details

Only CBOR certificates are allowed by this profile. Other certificate types,
such as X.509, must not be used.

### Mode

A certificate must only set the mode to `normal` when all of the following
conditions are met when loading and verifying the software component that is
being described by the certificate:

*   secure/verified boot with anti-rollback protection is enabled
*   only the secure/verified boot authorities for production images are enabled
*   debug ports, fuses, or other debug facilities are disabled
*   device booted software from the normal primary source e.g. internal flash

The mode should never be `not configured`.

### Configuration descriptor

The configuration descriptor is a CBOR map. Only key values less than -65536
are used as this is conventionally reserved for private use in IANA
assignments. The key value range \[-70000, -70999\] is reserved for use by this
profile. Implementation-specific fields may be added using key values outside
of the reserved range.

Unless explicitly stated as required in the [versions](#versions) section, each
field is optional. If no fields are relevant, an empty map should be encoded.

Name                   | Key    | Value type           | Meaning
---                    | ---    | ---                  | ---
Component&nbsp;name    | -70002 | tstr                 | Name of the component
Component&sbsp;version | -70003 | int&nbsp;/&nbsp;tstr | Version of the component
Resettable             | -70004 | null                 | If present, key changes on factory reset
Security&nbsp;version  | -70005 | uint                 | Machine-comparable, monotonically increasing version of the component where a greater value indicates a newer version, for example, the anti-rollback counter

### Versions

Android is an evolving ecosystem with compatibility requirements that enable
devices to continue being updated. Explicit versioning of certificates in the
DICE chain allows continued compatibility between higher-level software that
updates and lower-level software (such as ROM) that might not update.

Versions of this profile are identified by their profile name which is composed
of the prefix `"android."` followed by the Android version number it aligns
with. Certificates declare which profile they are following in the `profileName`
field defined by the [Open Profile for DICE](specification.md). If no profile
name is included in the certificate, `"android.14"` is assumed.

Within a DICE chain, the version of the profile used in each certificate must
be the same or greater than the version used in the previous certificate. This
ensures the all certificates are aware of, and can maintain, any chain
invariants that can be added in any version of the profile.

Android provides the [`hwtrust`][hwtrust-tool] tool which can validate that
certificate chains conform to this profile and can assist in diagnosing
problems.

[hwtrust-tool]: https://cs.android.com/android/platform/superproject/main/+/main:tools/security/remote_provisioning/hwtrust/README.md

The version-specific details listed below are non-cumulative so only apply to
the version they are listed under.

#### `"android.14"`

The profile named `"android.14"` aligns with Android 14.

*   Based on the [Open Profile for DICE v2.4][open-dice-v2.4].
*   The `configurationHash` field is permitted to be missing rather than being
    required, as specified by the Open Profile for DICE.
*   The `mode` field is permitted to be encoded as an integer rather than the
    byte string that is specified by the Open Profile for DICE.
*   The `keyUsage` field is permitted to be encoded in big-endian byte order as
    well as the little-endian byte order that is specified by the Open Profile
    for DICE. As a result of this erratum workaround, the value is ambiguous and
    verifiers might not be able to rely on this value.

#### `"android.15"`

The profile named `"android.15"` aligns with Android 15. It is backwards
compatible with the previous versions of the Andorid Profile for DICE.

*   Based on the [Open Profile for DICE v2.5][open-dice-v2.5].
*   The `configurationHash` field is permitted to be missing rather than being
    required, as specified by the Open Profile for DICE.

#### `"android.16"`

The profile named `"android.16"` aligns with Android 16 and is still subject to
change. It is backwards compatible with the previous versions of the Android
Profile for DICE.

*   Based on the [Open Profile for DICE v2.5][open-dice-v2.5].
*   The security version field of the [configuration
    descriptor](#configuration-descriptor) is required.

[open-dice-v2.4]: https://pigweed.googlesource.com/open-dice/+/f9f454ae493bfe76ec2af8011eb7543c20c5ffc2/docs/specification.md
[open-dice-v2.5]: https://pigweed.googlesource.com/open-dice/+/0b5044098bf9b40128927d675dea4ec1fb75c510/docs/specification.md
