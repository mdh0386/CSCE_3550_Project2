mod db;

use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1::{EncodeRsaPrivateKey, DecodeRsaPrivateKey, LineEnding},
    traits::PublicKeyParts,
};
use rand::rngs::OsRng;
use time::OffsetDateTime;
use chrono::Utc;
use jsonwebtoken::{encode as jwt_encode, EncodingKey};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use warp::Filter;

fn ensure_keys_in_db() {
    db::init_db().expect("Failed to init DB");

    // Ensure at least one valid and one expired key exists
    let valid = db::fetch_key(false).unwrap_or(None);
    let expired = db::fetch_key(true).unwrap_or(None);
    let hour = 3600i64;
    let now = OffsetDateTime::now_utc().unix_timestamp();

    if valid.is_none() {
        let mut rng = OsRng;
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pem = priv_key.to_pkcs1_pem(Default::default()).unwrap();
        db::insert_key(pem.as_bytes(), now + hour).unwrap();
    }

    if expired.is_none() {
        let mut rng = OsRng;
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pem = priv_key.to_pkcs1_pem(Default::default()).unwrap();
        db::insert_key(pem.as_bytes(), now - hour).unwrap();
    }
}

#[tokio::main]
async fn main() {
    ensure_keys_in_db();

    let method_not_allowed = warp::any().map(|| {
        warp::reply::with_status(
            "Method Not Allowed",
            warp::http::StatusCode::METHOD_NOT_ALLOWED,
        )
    });

    // JWT Auth endpoint
    let auth = warp::path("auth").and(
        warp::post()
            .and(warp::query::<HashMap<String, String>>())
            .map(|params: HashMap<String, String>| {
                let expired = params.get("expired").is_some();

                let keyrow = db::fetch_key(expired)
                    .unwrap()
                    .expect("No key in DB");

                let (kid, pem, _exp) = keyrow;
                let private_key = RsaPrivateKey::from_pkcs1_pem(std::str::from_utf8(&pem).unwrap()).unwrap();
                let private_key_pem = private_key.to_pkcs1_pem(LineEnding::LF).unwrap();
                let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).unwrap();

                let mut claims: BTreeMap<String, String> = BTreeMap::new();
                claims.insert("sub".to_string(), "1234567890".to_string());
                claims.insert("name".to_string(), "John Doe".to_string());
                claims.insert("iat".to_string(), "1516239022".to_string());

                let mut header = jsonwebtoken::Header::default();
                header.alg = jsonwebtoken::Algorithm::RS256;
                header.kid = Some(kid.to_string());

                let expiration = if expired {
                    Utc::now() - chrono::Duration::hours(1)
                } else {
                    Utc::now() + chrono::Duration::hours(1)
                };
                claims.insert("exp".to_string(), expiration.timestamp().to_string());

                let token = jwt_encode(&header, &claims, &encoding_key).unwrap();
                warp::reply::with_status(token, warp::http::StatusCode::OK)
            })
            .or(method_not_allowed),
    );

    // JWKS endpoint
    let jwks = warp::path!(".well-known" / "jwks.json").and(
        warp::get().map(move || {
            let keyrows = db::fetch_all_valid_keys().unwrap();
            let jwk_keys: Vec<_> = keyrows.iter().map(|(kid, pem, _exp)| {
                let private_key = RsaPrivateKey::from_pkcs1_pem(std::str::from_utf8(pem).unwrap()).unwrap();
                let public_key = RsaPublicKey::from(&private_key);
                let n = base64_url::encode(&public_key.n().to_bytes_be());
                let e = base64_url::encode(&public_key.e().to_bytes_be());
                json!({
                    "kty": "RSA",
                    "kid": kid.to_string(),
                    "use": "sig",
                    "n": n,
                    "e": e,
                    "alg": "RS256"
                })
            }).collect();
            warp::reply::json(&json!({ "keys": jwk_keys }))
        })
        .or(method_not_allowed),
    );

    let routes = auth.or(jwks);
    warp::serve(routes).run(([127, 0, 0, 1], 8080)).await;
}
