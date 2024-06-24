use std::collections::BTreeMap;

use ciborium::Value;
use cipher::{BlockDecryptMut as _, BlockEncryptMut as _, KeyIvInit};
use hmac::Mac;
use rand::RngCore as _;

pub struct KeyAgreementKey(p256::ecdh::EphemeralSecret);

impl KeyAgreementKey {
    pub fn generate() -> Self {
        Self(p256::ecdh::EphemeralSecret::random(&mut rand::thread_rng()))
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key())
    }

    pub fn shared_secret(&self, peer: &PublicKey) -> SharedSecret {
        let shared_point = self.0.diffie_hellman(&peer.0);
        let hkdf = shared_point.extract::<sha2::Sha256>(Some(&[0; 32]));
        let mut hmac_key = [0; 32];
        let mut aes_key = [0; 32];
        hkdf.expand(b"CTAP2 HMAC key", &mut hmac_key).unwrap();
        hkdf.expand(b"CTAP2 AES key", &mut aes_key).unwrap();
        SharedSecret { hmac_key, aes_key }
    }
}

pub struct PublicKey(p256::PublicKey);

impl From<PublicKey> for Value {
    fn from(public_key: PublicKey) -> Value {
        let encoded = p256::EncodedPoint::from(&public_key.0);
        let mut map = Map::default();
        map.push(1, 2);
        map.push(3, -25);
        map.push(-1, 1);
        map.push(-2, encoded.x().unwrap().as_slice());
        map.push(-3, encoded.y().unwrap().as_slice());
        map.into()
    }
}

impl From<Value> for PublicKey {
    fn from(value: Value) -> Self {
        let map: BTreeMap<i8, Value> = value.deserialized().unwrap();
        let kty = map.get(&1).unwrap();
        let alg = map.get(&3).unwrap();
        let crv = map.get(&-1).unwrap();
        let x = map.get(&-2).unwrap().as_bytes().unwrap().as_slice();
        let y = map.get(&-3).unwrap().as_bytes().unwrap().as_slice();

        assert_eq!(kty, &Value::from(2));
        assert_eq!(alg, &Value::from(-25));
        assert_eq!(crv, &Value::from(1));
        let encoded = p256::EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
        Self(encoded.try_into().unwrap())
    }
}

pub struct SharedSecret {
    hmac_key: [u8; 32],
    aes_key: [u8; 32],
}

impl SharedSecret {
    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        let mut iv = [0; 16];
        rand::thread_rng().fill_bytes(&mut iv);

        let cipher: cbc::Encryptor<aes::Aes256> =
            KeyIvInit::new(self.aes_key.as_ref().into(), iv.as_ref().into());
        let encrypted = cipher.encrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(data);

        let mut result = Vec::new();
        result.extend_from_slice(&iv);
        result.extend_from_slice(&encrypted);
        result
    }

    pub fn decrypt_pin_token(&self, data: &[u8]) -> PinToken {
        let (iv, data) = data.split_first_chunk::<16>().unwrap();
        let cipher: cbc::Decryptor<aes::Aes256> =
            KeyIvInit::new(self.aes_key.as_ref().into(), iv.into());
        let pin_token = cipher
            .decrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(data)
            .unwrap();
        PinToken(pin_token.try_into().unwrap())
    }

    pub fn authenticate(&self, data: &[u8]) -> [u8; 32] {
        let mut mac: hmac::Hmac<sha2::Sha256> = Mac::new_from_slice(&self.hmac_key).unwrap();
        mac.update(data);
        mac.finalize().into_bytes().into()
    }
}

pub struct PinToken([u8; 32]);

impl PinToken {
    pub fn authenticate(&self, data: &[u8]) -> [u8; 32] {
        let mut mac: hmac::Hmac<sha2::Sha256> = Mac::new_from_slice(&self.0).unwrap();
        mac.update(data);
        mac.finalize().into_bytes().into()
    }
}

#[derive(Default)]
pub struct Map(Vec<(Value, Value)>);

impl Map {
    pub fn push(&mut self, key: impl Into<Value>, value: impl Into<Value>) {
        self.0.push((key.into(), value.into()));
    }
}

impl From<Map> for Value {
    fn from(map: Map) -> Value {
        Value::from(map.0)
    }
}

pub trait Request: Into<Value> {
    const COMMAND: u8;

    type Reply: From<Value>;
}

pub struct ClientPin {
    protocol: u8,
    subcommand: u8,
    pub key_agreement: Option<PublicKey>,
    pub pin_auth: Option<[u8; 32]>,
    pub new_pin_enc: Option<Vec<u8>>,
    pub pin_hash_enc: Option<Vec<u8>>,
    pub permissions: Option<u8>,
    pub rp_id: Option<String>,
}

impl ClientPin {
    pub fn new(protocol: u8, subcommand: u8) -> Self {
        Self {
            protocol,
            subcommand,
            key_agreement: None,
            new_pin_enc: None,
            pin_hash_enc: None,
            permissions: None,
            pin_auth: None,
            rp_id: None,
        }
    }
}

impl From<ClientPin> for Value {
    fn from(request: ClientPin) -> Self {
        let mut map = Map::default();
        map.push(1, request.protocol);
        map.push(2, request.subcommand);
        if let Some(key_agreement) = request.key_agreement {
            map.push(3, key_agreement);
        }
        if let Some(pin_auth) = request.pin_auth {
            map.push(4, pin_auth.as_slice());
        }
        if let Some(new_pin_enc) = request.new_pin_enc {
            map.push(5, new_pin_enc);
        }
        if let Some(pin_hash_enc) = request.pin_hash_enc {
            map.push(6, pin_hash_enc);
        }
        if let Some(permissions) = request.permissions {
            map.push(9, permissions);
        }
        if let Some(rp_id) = request.rp_id {
            map.push(0x0a, rp_id);
        }
        map.into()
    }
}

impl Request for ClientPin {
    const COMMAND: u8 = 0x06;

    type Reply = ClientPinReply;
}

pub struct ClientPinReply {
    pub key_agreement: Option<Value>,
    pub pin_token: Option<Value>,
}

impl From<Value> for ClientPinReply {
    fn from(value: Value) -> Self {
        let mut map: BTreeMap<u8, Value> = value.deserialized().unwrap();
        Self {
            key_agreement: map.remove(&1),
            pin_token: map.remove(&2),
        }
    }
}

pub struct Rp {
    id: String,
    name: Option<String>,
}

impl Rp {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: None,
        }
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
}

impl From<Rp> for Value {
    fn from(rp: Rp) -> Value {
        let mut map = Map::default();
        map.push("id", rp.id);
        if let Some(name) = rp.name {
            map.push("name", name);
        }
        map.into()
    }
}

pub struct User {
    id: Vec<u8>,
    name: Option<String>,
    display_name: Option<String>,
}

impl User {
    pub fn new(id: impl Into<Vec<u8>>) -> Self {
        Self {
            id: id.into(),
            name: None,
            display_name: None,
        }
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = Some(display_name.into());
        self
    }
}

impl From<User> for Value {
    fn from(user: User) -> Value {
        let mut map = Map::default();
        map.push("id", user.id);
        if let Some(name) = user.name {
            map.push("name", name);
        }
        if let Some(display_name) = user.display_name {
            map.push("displayName", display_name);
        }
        map.into()
    }
}

pub struct PubKeyCredParam {
    ty: String,
    alg: i32,
}

impl PubKeyCredParam {
    pub fn new(ty: impl Into<String>, alg: impl Into<i32>) -> Self {
        Self {
            ty: ty.into(),
            alg: alg.into(),
        }
    }
}

impl From<PubKeyCredParam> for Value {
    fn from(param: PubKeyCredParam) -> Value {
        let mut map = Map::default();
        map.push("type", param.ty);
        map.push("alg", param.alg);
        map.into()
    }
}

pub struct MakeCredential {
    client_data_hash: Vec<u8>,
    rp: Rp,
    user: User,
    pub_key_cred_params: Vec<PubKeyCredParam>,
    pub options: Option<MakeCredentialOptions>,
    pub pin_auth: Option<[u8; 32]>,
    pub pin_protocol: Option<u8>,
}

impl MakeCredential {
    pub fn new(
        client_data_hash: impl Into<Vec<u8>>,
        rp: Rp,
        user: User,
        pub_key_cred_params: impl Into<Vec<PubKeyCredParam>>,
    ) -> Self {
        Self {
            client_data_hash: client_data_hash.into(),
            rp,
            user,
            pub_key_cred_params: pub_key_cred_params.into(),
            options: None,
            pin_auth: None,
            pin_protocol: None,
        }
    }
}

impl From<MakeCredential> for Value {
    fn from(request: MakeCredential) -> Value {
        let mut map = Map::default();
        map.push(1, request.client_data_hash);
        map.push(2, request.rp);
        map.push(3, request.user);
        map.push(
            4,
            request
                .pub_key_cred_params
                .into_iter()
                .map(Value::from)
                .collect::<Vec<_>>(),
        );
        if let Some(options) = request.options {
            map.push(7, options);
        }
        if let Some(pin_auth) = request.pin_auth {
            map.push(8, pin_auth.as_slice());
        }
        if let Some(pin_protocol) = request.pin_protocol {
            map.push(9, pin_protocol);
        }
        map.into()
    }
}

#[derive(Default)]
pub struct MakeCredentialOptions {
    rk: Option<bool>,
    up: Option<bool>,
    uv: Option<bool>,
}

impl MakeCredentialOptions {
    pub fn rk(mut self, rk: bool) -> Self {
        self.rk = Some(rk);
        self
    }

    pub fn up(mut self, up: bool) -> Self {
        self.up = Some(up);
        self
    }

    pub fn uv(mut self, uv: bool) -> Self {
        self.uv = Some(uv);
        self
    }
}

impl From<MakeCredentialOptions> for Value {
    fn from(options: MakeCredentialOptions) -> Value {
        let mut map = Map::default();
        if let Some(rk) = options.rk {
            map.push("rk", rk);
        }
        if let Some(up) = options.up {
            map.push("up", up);
        }
        if let Some(uv) = options.uv {
            map.push("uv", uv);
        }
        map.into()
    }
}

impl Request for MakeCredential {
    const COMMAND: u8 = 0x01;

    type Reply = MakeCredentialReply;
}

#[derive(Debug, PartialEq)]
pub struct MakeCredentialReply {
    pub fmt: String,
    pub auth_data: Value,
    pub att_stmt: Value,
}

impl From<Value> for MakeCredentialReply {
    fn from(value: Value) -> Self {
        let mut map: BTreeMap<u8, Value> = value.deserialized().unwrap();
        Self {
            fmt: map.remove(&1).unwrap().deserialized().unwrap(),
            auth_data: map.remove(&2).unwrap(),
            att_stmt: map.remove(&3).unwrap(),
        }
    }
}

pub struct GetInfo;

impl From<GetInfo> for Value {
    fn from(_: GetInfo) -> Self {
        Self::Null
    }
}

impl Request for GetInfo {
    const COMMAND: u8 = 0x04;

    type Reply = GetInfoReply;
}

pub struct GetInfoReply {
    pub versions: Vec<String>,
    pub aaguid: Value,
    pub pin_protocols: Option<Vec<u8>>,
}

impl From<Value> for GetInfoReply {
    fn from(value: Value) -> Self {
        let mut map: BTreeMap<u8, Value> = value.deserialized().unwrap();
        Self {
            versions: map.remove(&1).unwrap().deserialized().unwrap(),
            aaguid: map.remove(&3).unwrap().deserialized().unwrap(),
            pin_protocols: map.remove(&6).map(|value| value.deserialized().unwrap()),
        }
    }
}

pub struct CredentialManagement {
    pub subcommand: u8,
    pub subcommand_params: Option<CredentialManagementParams>,
    pub pin_protocol: u8,
    pub pin_auth: [u8; 32],
}

impl From<CredentialManagement> for Value {
    fn from(request: CredentialManagement) -> Value {
        let mut map = Map::default();
        map.push(1, request.subcommand);
        if let Some(subcommand_params) = request.subcommand_params {
            map.push(2, subcommand_params);
        }
        map.push(3, request.pin_protocol);
        map.push(4, request.pin_auth.as_slice());
        map.into()
    }
}

impl Request for CredentialManagement {
    const COMMAND: u8 = 0x0A;

    type Reply = CredentialManagementReply;
}

#[derive(Clone)]
pub struct CredentialManagementParams {
    pub rp_id_hash: Vec<u8>,
}

impl CredentialManagementParams {
    pub fn serialized(&self) -> Vec<u8> {
        let mut serialized = Vec::new();
        ciborium::into_writer(&Value::from(self.clone()), &mut serialized).unwrap();
        serialized
    }
}

impl From<CredentialManagementParams> for Value {
    fn from(params: CredentialManagementParams) -> Value {
        let mut map = Map::default();
        map.push(1, params.rp_id_hash);
        map.into()
    }
}

pub struct CredentialManagementReply {
    pub rp: Option<Value>,
    pub rp_id_hash: Option<Value>,
    pub total_rps: Option<usize>,
    pub user: Option<Value>,
    pub total_credentials: Option<usize>,
}

impl From<Value> for CredentialManagementReply {
    fn from(value: Value) -> Self {
        let mut map: BTreeMap<u8, Value> = value.deserialized().unwrap();
        Self {
            rp: map.remove(&3),
            rp_id_hash: map.remove(&4),
            total_rps: map.remove(&5).map(|value| value.deserialized().unwrap()),
            user: map.remove(&6),
            total_credentials: map.remove(&9).map(|value| value.deserialized().unwrap()),
        }
    }
}
