# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
- Set the `makeCredUvNotRqd` CTAP option to `true` to indicate that we support
  makeCredential operations without user verification ([#26][])
- Ignore public key credential parameters with an unknown type, as required by
  the Webauthn spec ([#28][])
- Ignore user data with empty ID in getAssertion ([#32][])

[#26]: https://github.com/solokeys/fido-authenticator/issues/26
[#28]: https://github.com/solokeys/fido-authenticator/issues/28
[#32]: https://github.com/solokeys/fido-authenticator/issues/32

## [0.1.1] - 2022-08-22
- Fix bug that treated U2F payloads as APDU over APDU in NFC transport @conorpp
- Add config option to skip UP when device was just booted,
  as insertion is a kind of UP check @robin-nitrokey

## [Unreleased]

- use 2021 edition
- use @szszszsz's credential ID shortening
- get rid of the two big heaps, only cache timestamp + filename in GetAssertion
- bump to the released dependencies
- integrate `dispatch-fido`
