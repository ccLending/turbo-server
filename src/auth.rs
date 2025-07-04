use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, errors::Error};
use serde::{Serialize, Deserialize};
use chrono::{Utc, Duration};
use actix_web::{FromRequest, HttpRequest, dev::Payload, Error as ActixError};
use futures::future::{ready, Ready};

const JWT_SECRET: &[u8] = b"turbo_super_secretkey"; 

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: i32,
    pub exp: usize,
    pub is_admin: bool,
}

pub fn generate_jwt(user_id: i32, is_admin: bool) -> Result<String, Error> {
    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(24))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: user_id,
        exp: expiration as usize,
        is_admin,
    };  

    encode(&Header::default(), &claims, &EncodingKey::from_secret(JWT_SECRET))
}

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: i32,
}

impl FromRequest for AuthUser {
    type Error = ActixError;
    type Future = Ready<Result<Self, Self::Error>>;
    
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        if let Some(header) = req.headers().get("Authorization") {
            if let Ok(auth_str) = header.to_str() {
                if auth_str.starts_with("Bearer ") {
                    let token = &auth_str[7..];
                    let result = decode::<Claims>(
                        token,
                        &DecodingKey::from_secret(JWT_SECRET),
                        &Validation::default(),
                    );
                    if let Ok(data) = result {
                        return ready(Ok(AuthUser {
                            user_id: data.claims.sub,
                        }));
                    }
                }
            }
        }
        ready(Err(actix_web::error::ErrorUnauthorized(
            serde_json::json!({"code": 201, "message": "Token已失效，请重新登录"})
        )))
    }
}

#[derive(Debug, Clone)]
pub struct AuthAdmin {
    pub user_id: i32,
}

impl FromRequest for AuthAdmin {
    type Error = ActixError;
    type Future = Ready<Result<Self, Self::Error>>;
    
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        if let Some(header) = req.headers().get("Authorization") {
            if let Ok(auth_str) = header.to_str() {
                if auth_str.starts_with("Bearer ") {
                    let token = &auth_str[7..];
                    let result = decode::<Claims>(
                        token,
                        &DecodingKey::from_secret(JWT_SECRET),
                        &Validation::default(),
                    );
                    if let Ok(data) = result {
                        if data.claims.is_admin {
                            return ready(Ok(AuthAdmin {
                                user_id: data.claims.sub,
                            }));
                        } else {
                            return ready(Err(actix_web::error::ErrorUnauthorized(
                                serde_json::json!({"code": 202, "message": "没有管理员操作权限"})
                            )));
                        }
                    }
                }
            }
        }
        ready(Err(actix_web::error::ErrorUnauthorized(
            serde_json::json!({"code": 201, "message": "Token已失效，请重新登录"})
        )))
    }
}
