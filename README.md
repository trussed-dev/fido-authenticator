# fido-authenticator

[FIDO][fido] authenticator [Trussed][trussed]<sup>®</sup> app.

Built with [Trussed][trussed].

As used in the [SoloKeys][solokeys] [Solo 2][solo2] and [Nitrokey 3][nitro3].

### Specifications

- [Client to Authenticator Protocol (CTAP)][ctap21ps]
- [W3C Web Authentication][webauthnl2]

[fido]: https://fidoalliance.org/
[trussed]: https://trussed.dev/
[solokeys]: https://solokeys.com/
[solo2]: https://solo2.dev/
[nitro3]: https://www.nitrokey.com/news/2021/new-nitrokey-3-nfc-usb-c-rust-common-criteria-eal-6/
[ctap21ps]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html
[webauthnl2]: https://www.w3.org/TR/webauthn-2/

### Setup

For attestation to work, the authenticator's state needs to be provisioned with a batch
attestation key and certificate. They are expected in files `/fido/sec/00` and `/fido/x5c/00`,
respectively.

In the context of the SoloKeys Solo 2, "secure" devices are pre-provisioned; for "unlocked" devices,
if the firmware contains the provisioner app, this can be done with the CLI:

```sh
solo2 pki dev fido batch.key batch.cert
solo2 app provision store-fido-batch-key batch.key
solo2 app provision store-fido-batch-cert batch.cert
```

#### License

`fido-authenticator` is fully open source.

All software, unless otherwise noted, is dual licensed under [Apache 2.0](LICENSE-APACHE) and [MIT](LICENSE-MIT).
You may use `fido-authenticator` software under the terms of either the Apache 2.0 license or MIT license.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

All documentation, unless otherwise noted, is licensed under [CC-BY-SA](https://creativecommons.org/licenses/by-sa/4.0/).
You may use `fido-authenticator` documentation under the terms of the CC-BY-SA 4.0 license.
