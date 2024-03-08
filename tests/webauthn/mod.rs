use ciborium::Value;

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

pub struct MakeCredentialRequest {
    client_data_hash: Vec<u8>,
    rp: Rp,
    user: User,
    pub_key_cred_params: Vec<PubKeyCredParam>,
}

impl MakeCredentialRequest {
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
        }
    }
}

impl From<MakeCredentialRequest> for Value {
    fn from(request: MakeCredentialRequest) -> Value {
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
        map.into()
    }
}
