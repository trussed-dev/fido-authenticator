# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

- Fix signature counter to improve spec compliance:
  - Set the initial signature counter to 1.
  - Correctly handle signature counter overflows by returning 0.
  - Increment the signature counter by a positive random number per assertion.
- Add the `Config::new` method to create an instance with the default values.
- Add support for multiple credential ID versions and add the `credential_id_version` field to `Config`.
- Add `CredentialIdVersion::V2` using AES-256-GCM.

## [v0.4.0-rc.1](https://github.com/trussed-dev/fido-authenticator/releases/tag/v0.4.0-rc.1) (2026-05-29)

- Update to `ctap-types` v0.6.0-rc.2.
- Set `algorithms`, `authenticator_config_commands`, `firmware_version`, `max_serialized_large_blob_array` and `remaining_discoverable_credentials` in `get_info` and add `firmware_version` to `Config`.
- Implement these new extensions:
  - `credBlob`
  - `hmac-secret-mc`
  - `minPinLength`
- Implement the `alwaysUv` feature.
- Implement the `config` command with these subcommands:
  - `toggleAlwaysUv`
  - `setMinPINLength`
- Add `ccid_transport` to `Config` and set `transports` in `get_info` accordingly.
- Indicate support for `FIDO_2_3` in `get_info`.
- Load full credential from filesstem for getAssertion if an allow list is used with a discoverable credential.
- Use UTF-8 code points instead of bytes when checking the minimum length for PINs.
- Accept `up = true` in makeCredential.
- Fix PIN verification in `large_blobs_set`.

## [v0.3.0](https://github.com/trussed-dev/fido-authenticator/releases/tag/v0.3.0) (2026-03-25)

- Update dependencies:
  - `apdu-app` v0.2
  - `cosey` v0.4
  - `ctap-types` v0.5
  - `ctaphid-app` v0.2
  - `heapless` v0.9
  - `heapless-bytes` v0.5
  - `iso7816` v0.2
  - `trussed-chunked` v0.3
  - `trussed-core` v0.2
  - `trussed-fs-info` v0.3
  - `trussed-hkdf` v0.4

## [v0.2.0](https://github.com/trussed-dev/fido-authenticator/releases/tag/v0.2.0) (2025-09-02)

- Set the `makeCredUvNotRqd` CTAP option to `true` to indicate that we support
  makeCredential operations without user verification ([#26][])
- Ignore public key credential paramters with an unknown type, as required by
  the Webauthn spec ([#28][])
- Reject `rk` option in getAssertion ([#31][])
- Ignore user data with empty ID in getAssertion ([#32][])
- Allow three instead of two PIN retries per boot ([#35][])
- Add log messages for requests, responses and errors
- Add config option for setting a maximum number of resident credentials.
- Reduce ID length for new credentials ([#37][])
- Update apdu-dispatch and reject calls to `select` ([#40][])
- Implement the `largeBlobKey` extension and the `largeBlobs` command ([#38][])
- Fix error type for third invalid PIN entry ([#60][])
- Fix error type for cancelled user presence ([#61][])
- PIN protocol changes:
  - Extract PIN protocol implementation into separate module ([#62][])
  - Implement PIN protocol 2 ([#63][])
  - Implement PIN token permissions ([#63][])
- Implement UpdateUserInformation subcommand for CredentialManagement
- Support CTAP 2.1
- Serialize PIN hash with `serde-bytes` ([#52][])
- Reduce the space taken by credential serialization ([#59][])
- Update dependencies:
  - Replace `trussed` dependency with `trussed-core`
  - Replace `ctaphid-dispatch` dependeny with `ctaphid-app`
- Remove the per-relying party directory to save space ([#55][])

[#26]: https://github.com/solokeys/fido-authenticator/issues/26
[#28]: https://github.com/solokeys/fido-authenticator/issues/28
[#31]: https://github.com/solokeys/fido-authenticator/issues/31
[#32]: https://github.com/solokeys/fido-authenticator/issues/32
[#35]: https://github.com/solokeys/fido-authenticator/issues/35
[#37]: https://github.com/solokeys/fido-authenticator/issues/37
[#40]: https://github.com/nitrokey/fido-authenticator/pull/40
[#38]: https://github.com/Nitrokey/fido-authenticator/issues/38
[#60]: https://github.com/Nitrokey/fido-authenticator/pull/60
[#61]: https://github.com/Nitrokey/fido-authenticator/pull/61
[#62]: https://github.com/Nitrokey/fido-authenticator/pull/62
[#63]: https://github.com/Nitrokey/fido-authenticator/pull/63
[#52]: https://github.com/Nitrokey/fido-authenticator/issues/52
[#59]: https://github.com/Nitrokey/fido-authenticator/issues/59
[#55]: https://github.com/Nitrokey/fido-authenticator/issues/55

## [0.1.1] - 2022-08-22
- Fix bug that treated U2F payloads as APDU over APDU in NFC transport @conorpp
- Add config option to skip UP when device was just booted,
  as insertion is a kind of UP check @robin-nitrokey

## [0.1.0] - 2022-03-17

- use 2021 edition
- use @szszszsz's credential ID shortening
- get rid of the two big heaps, only cache timestamp + filename in GetAssertion
- bump to the released dependencies
- integrate `dispatch-fido`
