# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
- Add config option for setting a maximum number of resident credentials.
- Ignore public key credential paramters with an unknown type, as required by
  the Webauthn spec ([#28][])
- Set the `makeCredUvNotRqd` CTAP option to `true` to indicate that we support
  makeCredential operations without user verification ([#26][])
- Reject `rk` option in getAssertion ([#31][])
- Ignore user data with empty ID in getAssertion ([#32][])
- Allow three instead of two PIN retries per boot ([#35][])
- Reduce ID length for new credentials ([#37][])
- Update apdu-dispatch and reject calls to `select` ([#40][])
- Implement the `largeBlobKey` extension and the `largeBlobs` command ([#38][])
- Fix error type for third invalid PIN entry ([#60][])
- Fix error type for cancelled user presence ([#61][])
- Extract PIN protocol implementation into separate module ([#62][])

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
