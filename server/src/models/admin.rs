use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct CreateClientReq {
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub is_confidential: bool,
}

#[derive(Serialize, Deserialize)]
pub struct ClientRes {
    pub id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}
