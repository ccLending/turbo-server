mod auth;
mod models;
mod schema;

use actix_web::{post, get, web, App, HttpServer, Responder, HttpResponse};
use actix_web::web::PayloadConfig;
use actix_web::http::header::DispositionParam;
use actix_multipart::Multipart;
use actix_files::Files;
use actix_cors::Cors;

use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use diesel::pg::PgConnection;
use diesel::dsl::sql;
use diesel::sql_query;
use diesel::sql_types::*;
use diesel::dsl::count_star;
use diesel::dsl::sum;

use serde::{Deserialize, Serialize};
use dotenvy::dotenv;
use std::env;
use bcrypt::{hash, verify, DEFAULT_COST};
use regex::Regex;
use chrono::{Local, DateTime, Duration, Timelike, TimeZone};
use bigdecimal::{BigDecimal, num_bigint::ToBigInt};
use futures_util::stream::StreamExt;
use tokio::fs;

use crate::auth::{generate_jwt, AuthUser, AuthAdmin};
use crate::schema::{accounts, creations, collections, assets, trade_orders, personal_auth, business_auth, balance_logs, system_config, boosts, banners, transfers};
use crate::models::{
    Account, NewAccount, Creation, NewCreation, Collection, Asset, TradeOrder, NewTradeOrder, KlineData, 
    SystemConfig, PersonalAuth, BusinessAuth, VipPlan, BalanceLog, NewBalanceLog, BoostPlan, 
    Banner, NewBanner, SmsCode, Transfer, NewTransfer,
};

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>; 

fn is_valid_password(pwd: &str) -> bool {
    let len_ok = pwd.len() >= 8 && pwd.len() <= 30;
    let re_upper = Regex::new(r"[A-Z]").unwrap();
    let re_lower = Regex::new(r"[a-z]").unwrap();
    let re_digit = Regex::new(r"[0-9]").unwrap();

    len_ok &&
    re_upper.is_match(pwd) &&
    re_lower.is_match(pwd) &&
    re_digit.is_match(pwd)
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    code: u16,
    message: String,
}

#[post("/register")]
async fn register_account(
    info: web::Json<NewAccount>, 
    pool: web::Data<DbPool>
) -> impl Responder {
    use crate::schema::accounts::dsl::*;

    let conn = &mut pool.get().expect("couldn't get db connection from pool");
    let mut new_account = info.into_inner();
    if !is_valid_password(&new_account.login_password) {
        return HttpResponse::BadRequest().json(ErrorResponse { code: 101, message: "密码长度8-30位，包含大小写字母和数字".into() });
    }
    match hash(&new_account.login_password, DEFAULT_COST) {
        Ok(hashed_pwd) => new_account.login_password = hashed_pwd,
        Err(_) => return HttpResponse::InternalServerError().body("Hashing failed"),
    }

    let result = conn.transaction::<_, diesel::result::Error, _>(|conn| {
        let inserted: Account = diesel::insert_into(accounts)
            .values(&new_account)
            .get_result(conn)?;
        diesel::update(accounts.filter(user_id.eq(inserted.user_id)))
            .set((
                nickname.eq(&format!("用户{}", inserted.user_id)),
                avatar.eq("/avatars/default.png"),
            ))
            .execute(conn)?;
        Ok(inserted)
    });

    match result {
        Ok(_) => HttpResponse::Ok().json(ErrorResponse { code: 0, message: "账号注册成功".into() }),
        Err(_) => HttpResponse::BadRequest().json(ErrorResponse { code: 102, message: "手机号已经注册过了".into() }),
    }
}

#[derive(Deserialize)]
struct LoginRequest {
    phone: String,
    password: String,
}

#[derive(Serialize)]
pub struct AccountInfo {
    pub user_id: i32,
    pub phone: String,
    pub nickname: Option<String>,
    pub avatar: Option<String>,
    pub is_verified: Option<bool>,
    pub is_vip: Option<bool>,
    pub vip_expire_at: Option<DateTime<Local>>,
    pub account_type: Option<String>,
    pub total_asset_today: Option<BigDecimal>,
    pub total_asset_yesterday: Option<BigDecimal>,
    pub balance: Option<BigDecimal>,
    pub frozen_amount: Option<BigDecimal>,
    pub is_trade_password_set: bool,
    pub pnl_ratio: Option<BigDecimal>,
}

impl From<Account> for AccountInfo {
    fn from(account: Account) -> Self {
        Self {
            user_id: account.user_id,
            phone: account.phone,
            nickname: account.nickname,
            avatar: account.avatar,
            is_verified: account.is_verified,
            is_vip: account.is_vip,
            vip_expire_at: account.vip_expire_at,
            account_type: account.account_type,
            total_asset_today: account.total_asset_today.clone(),
            total_asset_yesterday: account.total_asset_yesterday.clone(),
            balance: account.balance,
            frozen_amount: account.frozen_amount,
            is_trade_password_set: account.trade_password.is_some(),
            pnl_ratio: match (&account.total_asset_today, &account.total_asset_yesterday) {
                (Some(t), Some(y)) if *y != BigDecimal::from(0) => {
                    let ratio = (t - y) / y * BigDecimal::from(100);
                    Some(ratio.with_scale(2))
                }
                _ => None,
            },
        }
    }
}

#[derive(Serialize)]
struct LoginSuccess {
    code: u16,
    jwt: String,
    account: AccountInfo,
}

#[derive(Serialize)]
struct LoginFailure {
    code: u16,
    message: String,
    remaining: i32,
}

enum LoginOutcome {
    Success(LoginSuccess),
    Failure(LoginFailure),
}

#[post("/login")]
async fn login_account(
    login: web::Json<LoginRequest>,
    pool: web::Data<DbPool>,
) -> impl Responder {
    use crate::schema::accounts::dsl::*;

    let conn = &mut pool.get().expect("DB connection error");
    let result = conn.transaction::<_, diesel::result::Error, _>(|conn| {
        let mut account: Account = accounts
            .filter(phone.eq(&login.phone))
            .first(conn)?;
        if let Some("deleted") = account.account_status.as_deref() {
            return Ok(LoginOutcome::Failure(LoginFailure { code: 105, message: "账号已注销。如果要恢复账号可联系客户。".into(), remaining: 0}));
        }
        
        if let Some(unlock_time) = account.unlock_time_if_locked {
            if Local::now() < unlock_time {
                let remaining = (unlock_time - Local::now()).num_minutes() as i32;
                return Ok(LoginOutcome::Failure(LoginFailure { code: 104, message: format!("账号被临时锁定，{}分钟后再试。", remaining), remaining}));
            } else {
                diesel::update(accounts.filter(user_id.eq(account.user_id)))
                    .set((
                        account_status.eq("active"),
                        login_retry_count.eq(0),
                        unlock_time_if_locked.eq::<Option<DateTime<Local>>>(None),
                    ))
                    .execute(conn)?;
            }
        }

        if !verify(&login.password, &account.login_password).unwrap_or(false) {
            let retry_count = account.login_retry_count.unwrap_or(0) + 1;
            let remaining_attempts = 5 - retry_count;
            if retry_count >= 5 {
                diesel::update(accounts.filter(user_id.eq(account.user_id)))
                    .set((
                        login_retry_count.eq(retry_count),
                        account_status.eq("locked"),
                        unlock_time_if_locked.eq(Local::now() + Duration::hours(1)),
                    ))
                    .execute(conn)?;
            } else {
                diesel::update(accounts.filter(user_id.eq(account.user_id)))
                    .set(login_retry_count.eq(retry_count))
                    .execute(conn)?;
            }
            let remaining = remaining_attempts as i32;
            return Ok(LoginOutcome::Failure(LoginFailure { code: 103, message: format!("登录失败, 超过5次账户会被临时锁定。你还有{}次重试机会。", remaining), remaining}));
        } 

        if account.login_retry_count.map_or(false, |count| count > 0) {
            diesel::update(accounts.filter(user_id.eq(account.user_id)))
                .set(login_retry_count.eq(0))
                .execute(conn)?;
        }
         
        if account.is_vip == Some(true) && account.vip_expire_at.map_or(true, |expire| expire < Local::now()) {
            account.is_vip = Some(false);
            diesel::update(accounts.filter(user_id.eq(account.user_id)))
                .set(is_vip.eq(false))
                .execute(conn)?;
        }
        
        let total_asset: Option<BigDecimal> = assets::table
            .inner_join(collections::table.on(assets::collection_id.eq(collections::collection_id)))
            .filter(assets::owner_id.eq(account.user_id))
            .select(sum(collections::last_trade_price))
            .first(conn)?;
        if let Some(total_asset) = total_asset {
            diesel::update(accounts.filter(user_id.eq(account.user_id)))
                .set(total_asset_today.eq(total_asset.clone()))
                .execute(conn)?;
            account.total_asset_today = Some(total_asset);
        }

        let token = generate_jwt(account.user_id, account.is_admin.unwrap_or(false)).unwrap();
        Ok(LoginOutcome::Success(LoginSuccess { code: 0, jwt: token, account: account.into() }))
    });

    match result { 
        Ok(LoginOutcome::Success(success)) => HttpResponse::Ok().json(success),
        Ok(LoginOutcome::Failure(failure)) => HttpResponse::Ok().json(failure),
        Err(_) => HttpResponse::Unauthorized().json(ErrorResponse { code: 105, message: "无此用户".into() }),
    }
}

#[get("/user_info")]
async fn get_user_info(
    pool: web::Data<DbPool>,
    auth_user: AuthUser,
) -> impl Responder {
    use crate::schema::accounts::dsl::*;

    let conn = &mut pool.get().expect("Failed to get DB connection");
    let account: Account = accounts
        .filter(user_id.eq(&auth_user.user_id))
        .first(conn)
        .expect("User not found");
    
    let user_info: AccountInfo = account.into();
    #[derive(Serialize)]
    struct MyResponse {
        code: u16,
        user_info: AccountInfo,
    }
    HttpResponse::Ok().json( MyResponse {code: 0, user_info} )
}

#[derive(Deserialize)]
struct SetPasswordRequest {
    password: String,
}

#[post("/set_trade_password")]
async fn set_trade_password(
    auth_user: AuthUser,
    db: web::Data<DbPool>,
    info: web::Json<SetPasswordRequest>,
) -> actix_web::Result<HttpResponse> {
    use crate::schema::accounts::dsl::*;

    if !is_valid_password(&info.password) {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse { code: 101, message: "密码长度8-30位，包含大小写字母和数字".into() }));
    }
    let hashed_pwd = hash(&info.password, DEFAULT_COST).map_err(|_| actix_web::error::ErrorInternalServerError("Hashing failed"))?;

    let conn = &mut db.get().map_err(|_| actix_web::error::ErrorInternalServerError("无法获取数据库连接"))?;
    diesel::update(accounts.filter(user_id.eq(auth_user.user_id)))
        .set(trade_password.eq(&hashed_pwd))
        .execute(conn)
        .map_err(|_| actix_web::error::ErrorInternalServerError("更新失败"))?;

    Ok(HttpResponse::Ok().json(ErrorResponse { code: 0, message: "设置交易密码成功".into() }))
}

#[post("/change_trade_password")]
async fn change_trade_password(
    auth_user: AuthUser,
    db: web::Data<DbPool>,
    info: web::Json<SetPasswordRequest>,
) -> actix_web::Result<HttpResponse> {
    use crate::schema::accounts::dsl::*;

    if !is_valid_password(&info.password) {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse { code: 101, message: "密码长度8-30位，包含大小写字母和数字".into() }));
    }
    let hashed_pwd = hash(&info.password, DEFAULT_COST).map_err(|_| actix_web::error::ErrorInternalServerError("Hashing failed"))?;

    let conn = &mut db.get().map_err(|_| actix_web::error::ErrorInternalServerError("无法获取数据库连接"))?;
    diesel::update(accounts.filter(user_id.eq(auth_user.user_id)))
        .set(trade_password.eq(&hashed_pwd))
        .execute(conn)
        .map_err(|_| actix_web::error::ErrorInternalServerError("更新失败"))?;

    Ok(HttpResponse::Ok().json(ErrorResponse { code: 0, message: "修改交易密码成功".into() }))
}

#[post("/change_login_password")]
async fn change_login_password(
    auth_user: AuthUser,
    db: web::Data<DbPool>,
    info: web::Json<SetPasswordRequest>,
) -> actix_web::Result<HttpResponse> {
    use crate::schema::accounts::dsl::*;

    if !is_valid_password(&info.password) {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse { code: 101, message: "密码长度8-30位，包含大小写字母和数字".into() }));
    }
    let hashed_pwd = hash(&info.password, DEFAULT_COST).map_err(|_| actix_web::error::ErrorInternalServerError("Hashing failed"))?;

    let conn = &mut db.get().map_err(|_| actix_web::error::ErrorInternalServerError("无法获取数据库连接"))?;
    diesel::update(accounts.filter(user_id.eq(auth_user.user_id)))
        .set(login_password.eq(&hashed_pwd))
        .execute(conn)
        .map_err(|_| actix_web::error::ErrorInternalServerError("更新失败"))?;

    Ok(HttpResponse::Ok().json(ErrorResponse { code: 0, message: "修改登录密码成功".into() }))
}

#[derive(Deserialize)]
struct ForgotPasswordRequest {
    phone: String,
    sms_code: String,
    new_password: String,
}

#[post("/forgot_password")]
async fn forgot_password(
    db: web::Data<DbPool>,
    req: web::Json<ForgotPasswordRequest>,
) -> impl Responder {
    use crate::schema::smscodes::dsl::*;
    let conn = &mut db.get().expect("db error");
    let sms = smscodes
        .filter(phone.eq(&req.phone))
        .first::<SmsCode>(conn)
        .optional()
        .expect("db error");
    let Some(sms) = sms else {
        return HttpResponse::BadRequest().json(ErrorResponse { code: 602, message: "手机号不正确".into() });
    };
    if sms.sms_code.as_ref() != Some(&req.sms_code) {
        return HttpResponse::BadRequest().json(ErrorResponse { code: 603, message: "手机验证码错误".into() });
    }
    if sms.expire_at.as_ref().map_or(true, |t| t < &Local::now()) {
        return HttpResponse::BadRequest().json(ErrorResponse { code: 604, message: "手机验证码已过期".into() });
    }
    if !is_valid_password(&req.new_password) {
        return HttpResponse::BadRequest().json(ErrorResponse { code: 101, message: "密码长度8-30位，包含大小写字母和数字".into() });
    }
    let hashed_pwd = hash(&req.new_password, DEFAULT_COST).expect("Hashing failed");

    diesel::update(accounts::table.filter(accounts::phone.eq(&req.phone)))
        .set(accounts::login_password.eq(&hashed_pwd))
        .execute(conn)
        .expect("db error");
    HttpResponse::Ok().json(ErrorResponse { code: 0, message: "重置密码成功".into() })
}

#[derive(Deserialize)]
struct SetPhoneRequest {
    phone: String,
}

#[post("/change_phone")]
async fn change_phone(
    auth_user: AuthUser,
    db: web::Data<DbPool>,
    info: web::Json<SetPhoneRequest>,
) -> actix_web::Result<HttpResponse> {
    use crate::schema::accounts::dsl::*;
    let conn = &mut db.get().map_err(|_| actix_web::error::ErrorInternalServerError("无法获取数据库连接"))?;
    diesel::update(accounts.filter(user_id.eq(auth_user.user_id)))
        .set(phone.eq(&info.phone))
        .execute(conn)
        .map_err(|_| actix_web::error::ErrorInternalServerError("更新失败"))?;

    Ok(HttpResponse::Ok().json(ErrorResponse { code: 0, message: "修改手机号成功".into() }))
}

#[post("/close_account")]
async fn close_account(
    auth_user: AuthUser,
    db: web::Data<DbPool>,
) -> actix_web::Result<HttpResponse> {
    use crate::schema::accounts::dsl::*;
    let conn = &mut db.get().map_err(|_| actix_web::error::ErrorInternalServerError("无法获取数据库连接"))?;
    diesel::update(accounts.filter(user_id.eq(auth_user.user_id)))
        .set(account_status.eq("deleted"))
        .execute(conn)
        .map_err(|_| actix_web::error::ErrorInternalServerError("更新失败"))?;

    Ok(HttpResponse::Ok().json(ErrorResponse { code: 0, message: "注销账户成功".into() }))
}

#[derive(Deserialize)]
struct ChangeNicknameRequest {
    nickname: String,
}

#[post("/change_nickname")]
async fn change_nickname(
    auth_user: AuthUser,
    db: web::Data<DbPool>,
    info: web::Json<ChangeNicknameRequest>,
) -> actix_web::Result<HttpResponse> {
    use crate::schema::accounts::dsl::*;

    if info.nickname.chars().count() > 10 {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse { code: 106, message: "昵称长度最多10个字符".into() }));
    }
    let conn = &mut db.get().map_err(|_| actix_web::error::ErrorInternalServerError("无法获取数据库连接"))?;
    diesel::update(accounts.filter(user_id.eq(auth_user.user_id)))
        .set(nickname.eq(&info.nickname))
        .execute(conn)
        .map_err(|_| actix_web::error::ErrorInternalServerError("更新失败"))?;
    Ok(HttpResponse::Ok().json(ErrorResponse { code: 0, message: "昵称已更新".into() }))
}

#[post("/upload_avatar")]
async fn upload_avatar(
    mut payload: Multipart,
    auth_user: AuthUser,
    db: web::Data<DbPool>,
) -> actix_web::Result<HttpResponse> {
    use crate::schema::accounts::dsl::*;
    let mut avatar_url = None;
    while let Some(field) = payload.next().await {
        let mut field = field?;
        let filename = format!("{}.png", uuid::Uuid::new_v4());
        let filepath = format!("./avatars/{}", filename);
    
        let mut f = fs::File::create(&filepath).await?;
        while let Some(chunk) = field.next().await {
            let data = chunk?;
            tokio::io::AsyncWriteExt::write_all(&mut f, &data).await?;
        }
        avatar_url = Some(format!("/avatars/{}", filename));
        break; 
    }
    let Some(url) = avatar_url else {
        return Ok(HttpResponse::BadRequest().body("No file uploaded"));
    };

    let conn = &mut db.get().expect("db conn");
    diesel::update(accounts.filter(user_id.eq(auth_user.user_id)))
        .set(avatar.eq(&url))
        .execute(conn)
        .map_err(|_| actix_web::error::ErrorInternalServerError("DB update failed"))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "code": 0, "avatar_url": url })))
}

#[post("/upload_image")]
async fn upload_image(
    mut payload: Multipart,
    _auth_user: AuthUser,
) -> actix_web::Result<HttpResponse> {
    let mut url = None;
    while let Some(field) = payload.next().await {
        let mut field = field?;
        let filename = format!("{}.png", uuid::Uuid::new_v4());
        let filepath = format!("./uploads/{}", filename);
    
        let mut f = fs::File::create(&filepath).await?;
        while let Some(chunk) = field.next().await {
            let data = chunk?;
            tokio::io::AsyncWriteExt::write_all(&mut f, &data).await?;
        }
        url = Some(format!("/uploads/{}", filename));
        break; 
    }
    let Some(url) = url else {
        return Ok(HttpResponse::BadRequest().body("No file uploaded"));
    };
    Ok(HttpResponse::Ok().json(serde_json::json!({ "code": 0, "url": url })))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewCreationRequest {
    pub title: String,
    pub cover_image: Option<String>,
    pub description: Option<String>,
    pub total_supply: i32,
    pub trade_option: Option<String>,
    pub trade_start_at: Option<DateTime<Local>>,
    pub issue_price: Option<BigDecimal>,
    pub presale_enabled: Option<bool>,
    pub presale_ratio: Option<BigDecimal>,
    pub presale_price: Option<BigDecimal>,
    pub presale_quantity: Option<i32>,
    pub sms_code: String,
}

#[derive(Serialize)]
pub struct CreationResponse {
    code: u16,
    message: String,
    creation: Creation,
}

#[post("/new_creation")]
async fn new_creation(
    auth_user: AuthUser,
    db: web::Data<DbPool>,
    info: web::Json<NewCreationRequest>,
) -> actix_web::Result<HttpResponse>   {
    use crate::schema::accounts::dsl::*;
    use crate::schema::creations::dsl::*;

    let conn = &mut db.get().expect("DB connection error");
    let mut req = info.into_inner();
    let user: Account = accounts
        .filter(user_id.eq(auth_user.user_id))
        .first(conn)
        .map_err(|_| actix_web::error::ErrorInternalServerError("未找到用户"))?;
    if user.sms_code != Some(req.sms_code) {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse { code: 603, message: "手机验证码错误".into() }));
    }
    if user.sms_code_expire_at.as_ref().map_or(true, |t| t < &Local::now()) {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse { code: 604, message: "手机验证码已过期".into() }));
    }
    let config: SystemConfig = system_config::table.first(conn).expect("db error");
    if user.balance.as_ref().map_or(true, |v| v < &config.issue_review) {
        return Ok(HttpResponse::BadRequest().json ( ErrorResponse { code: 120, message: format!("发行审核费用 {}元，你的余额不足，请充值。", config.issue_review.round(0)) }));
    }
    if user.is_verified != Some(true) {
        return Ok(HttpResponse::Forbidden().json(ErrorResponse { code: 110, message: "用户尚未认证，不能提交创作".into() }));
    }
    if req.title.len() > 26 {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse { code: 114, message: "标题长度最多8个中文字符，或26个英文字符".into() }));
    }
    if req.total_supply > 999 {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse { code: 115, message: "发行数量最大999".into() }));
    }
    if let Some("personal") = user.account_type.as_deref() {
        req.trade_option = Some("non-tradable".to_string());
        req.trade_start_at = None;
        req.issue_price = None;
        req.presale_enabled = Some(false);
        req.presale_ratio = None;
        req.presale_price = None;
    }
    if let Some("tradable") = req.trade_option.as_deref() {
        if req.trade_start_at.is_none() || req.issue_price.is_none() {
            return Ok(HttpResponse::BadRequest().json(ErrorResponse { code: 116, message: "需指定交易开启时间和发行价格".into() }));
        }
        if req.presale_enabled == Some(true) {
            if let Some(ratio) = req.presale_ratio.as_ref() {
                if *ratio <= BigDecimal::from(0) || *ratio >= BigDecimal::from(100) {
                    return Ok(HttpResponse::BadRequest().json(ErrorResponse { code: 117, message: "预售比例需大于0且小于100".into() }));  
                }
                let qty = ratio * BigDecimal::from(req.total_supply) / BigDecimal::from(100);
                req.presale_quantity = i32::try_from(qty.to_bigint().unwrap()).ok();
            } else {
                return Ok(HttpResponse::BadRequest().json(ErrorResponse { code: 118, message: "开启预售需指定预售比例".into() }));  
            }
            if req.presale_price.is_none() {
                return Ok(HttpResponse::BadRequest().json(ErrorResponse { code: 119, message: "开启预售需指定预售价格".into() }));  
            }
        }
    }

    let updated: Account = diesel::update(accounts.filter(user_id.eq(auth_user.user_id)))
        .set(balance.eq(balance - &config.issue_review))
        .get_result(conn)
        .expect("db error");
    let new_log = NewBalanceLog {
        account_id: auth_user.user_id,
        amount: -config.issue_review.clone(),
        balance_after: updated.balance.unwrap_or(0.into()) + updated.frozen_amount.unwrap_or(0.into()),
        opt_type: "check".into(),
        memo: Some("发行审核费用".into()),
        created_at: Some(Local::now()),
    };
    diesel::insert_into(balance_logs::table)
        .values(&new_log)
        .execute(conn)
        .expect("db error");

    let new_creation = NewCreation {
        creator_id: auth_user.user_id,
        title: req.title,
        cover_image: req.cover_image,
        description: req.description,
        total_supply: req.total_supply,
        trade_option: req.trade_option,
        trade_start_at: req.trade_start_at,
        issue_price: req.issue_price,
        presale_enabled: req.presale_enabled,
        presale_ratio: req.presale_ratio,
        presale_price: req.presale_price,
        review_status: Some("pending".to_string()),
        submitted_at: Some(Local::now()),
        rejected_at: None,
        reject_reason: None,
        contract_address: None,
        issued_at: None,
        presale_quantity: req.presale_quantity,
        presold_quantity: Some(0),
    };    
    let inserted: Creation = diesel::insert_into(creations)
        .values(&new_creation)
        .get_result(conn)
        .map_err(actix_web::error::ErrorInternalServerError)?;
    
    Ok(HttpResponse::Ok().json(CreationResponse {code: 0, message: "创作提交成功，请等待审核结果".into(), creation: inserted }))
}

#[derive(Deserialize)]
pub struct UpdateCreationRequest {
    pub creation_id: i32,
    pub title: String,
    pub description: Option<String>,
    pub cover_image: Option<String>,
    pub total_supply: i32,
    pub trade_option: Option<String>,
    pub trade_start_at: Option<DateTime<Local>>,
    pub issue_price: Option<BigDecimal>,
    pub presale_enabled: Option<bool>,
    pub presale_ratio: Option<BigDecimal>,
    pub presale_price: Option<BigDecimal>,
    pub presale_quantity: Option<i32>,
    pub sms_code: String,
}

#[post("/update_creation")]
async fn update_creation(
    auth_user: AuthUser,
    db: web::Data<DbPool>,
    info: web::Json<UpdateCreationRequest>,
) -> Result<HttpResponse, Box<dyn std::error::Error>> {
    use crate::schema::accounts::dsl::*;
    use crate::schema::creations::dsl::*;

    let conn = &mut db.get().expect("db error");
    let mut req = info.into_inner();
    if req.title.len() > 26 {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse { code: 114, message: "标题长度最多8个中文字符，或26个英文字符".into() }));
    }
    if req.total_supply > 999 {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse { code: 115, message: "发行数量最大999".into() }));
    }
    let target = creations
        .filter(creation_id.eq(req.creation_id))
        .first::<Creation>(conn)
        .optional()?;
    let Some(target) = target else {
        return Ok(HttpResponse::NotFound().json(ErrorResponse { code: 111, message: "无此作品".into() } ));
    };
    if target.creator_id != auth_user.user_id {
        return Ok(HttpResponse::Forbidden().json(ErrorResponse { code: 112, message: "权限错误，并非你的作品".into() }));
    }
    if target.review_status.as_deref() != Some("rejected") {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {code: 113, message: "修改操作仅限于被驳回的创作".into() }));
    }
    let user: Account = accounts
        .filter(user_id.eq(auth_user.user_id))
        .first(conn)?;
    if user.sms_code != Some(req.sms_code) {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse { code: 603, message: "手机验证码错误".into() }));
    }
    if user.sms_code_expire_at.as_ref().map_or(true, |t| t < &Local::now()) {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse { code: 604, message: "手机验证码已过期".into() }));
    }
    let config: SystemConfig = system_config::table.first(conn).expect("db error");
    if user.balance.as_ref().map_or(true, |v| v < &config.issue_review) {
        return Ok(HttpResponse::BadRequest().json ( ErrorResponse { code: 120, message: format!("发行审核费用 {}元，你的余额不足，请充值。", config.issue_review.round(0)) }));
    }
    if let Some("personal") = user.account_type.as_deref() {
        req.trade_option = Some("non-tradable".to_string());
        req.trade_start_at = None;
        req.issue_price = None;
        req.presale_enabled = Some(false);
        req.presale_ratio = None;
        req.presale_price = None;
    }
    if let Some("tradable") = req.trade_option.as_deref() {
        if req.trade_start_at.is_none() || req.issue_price.is_none() {
            return Ok(HttpResponse::BadRequest().json(ErrorResponse { code: 116, message: "需指定交易开启时间和发行价格".into() }));
        }
        if req.presale_enabled == Some(true) {
            if let Some(ratio) = req.presale_ratio.as_ref() {
                if *ratio <= BigDecimal::from(0) || *ratio >= BigDecimal::from(100) {
                    return Ok(HttpResponse::BadRequest().json(ErrorResponse { code: 117, message: "预售比例需大于0且小于100".into() }));  
                }
                let qty = ratio * BigDecimal::from(req.total_supply) / BigDecimal::from(100);
                req.presale_quantity = i32::try_from(qty.to_bigint().unwrap()).ok();
            } else {
                return Ok(HttpResponse::BadRequest().json(ErrorResponse { code: 118, message: "开启预售需指定预售比例".into() }));  
            }
            if req.presale_price.is_none() {
                return Ok(HttpResponse::BadRequest().json(ErrorResponse { code: 119, message: "开启预售需指定预售价格".into() }));  
            }
        }
    }

    let updated: Account = diesel::update(accounts.filter(user_id.eq(auth_user.user_id)))
        .set(balance.eq(balance - &config.issue_review))
        .get_result(conn)
        .expect("db error");
    let new_log = NewBalanceLog {
        account_id: auth_user.user_id,
        amount: -config.issue_review.clone(),
        balance_after: updated.balance.unwrap_or(0.into()) + updated.frozen_amount.unwrap_or(0.into()),
        opt_type: "check".into(),
        memo: Some("发行审核费用".into()),
        created_at: Some(Local::now()),
    };
    diesel::insert_into(balance_logs::table)
        .values(&new_log)
        .execute(conn)
        .expect("db error");

    let updated: Creation = diesel::update(creations.filter(creation_id.eq(req.creation_id)))
        .set((
            title.eq(req.title),
            description.eq(req.description),
            cover_image.eq(req.cover_image),
            total_supply.eq(req.total_supply),
            trade_option.eq(req.trade_option),
            trade_start_at.eq(req.trade_start_at),
            issue_price.eq(req.issue_price),
            presale_enabled.eq(req.presale_enabled),
            presale_ratio.eq(req.presale_ratio),
            presale_price.eq(req.presale_price),
            review_status.eq("pending"),
            submitted_at.eq(Local::now()),
            rejected_at.eq::<Option<DateTime<Local>>>(None),
            reject_reason.eq::<Option<String>>(None),
            presale_quantity.eq(req.presale_quantity),
        ))
        .get_result(conn)?;

    Ok(HttpResponse::Ok().json(CreationResponse {code: 0, message: "修改创作成功，请等待审核结果".into(), creation: updated }))
}

#[derive(Queryable, Serialize)]
struct MyCreation {
    #[serde(flatten)]
    creation: Creation,
    last_price: Option<BigDecimal>,
    change_ratio: Option<BigDecimal>,
}

#[get("/my_creations")]
async fn my_creations(
    pool: web::Data<DbPool>,
    auth_user: AuthUser,
) -> impl Responder {
    use crate::schema::creations::dsl::*;
    use crate::schema::collections::dsl::*;

    let conn = &mut pool.get().expect("db error");
    let rows: Vec<(Creation, Option<Collection>)> = creations
        .left_outer_join(collections.on(collection_id.eq(creation_id)))
        .filter(creator_id.eq(auth_user.user_id))
        .order(submitted_at.desc())
        .load(conn)
        .expect("db error");
    
    let results: Vec<MyCreation> = rows
        .into_iter()
        .map(|(creation, collection)| {
            let (last_price, change_ratio) = if let (Some(last_price), Some(issue_pr)) = (
                collection.as_ref().and_then(|c| c.last_trade_price.as_ref()),
                creation.issue_price.as_ref(),
            ) {
                if *issue_pr != BigDecimal::from(0) {
                    let change = (last_price - issue_pr) / issue_pr * BigDecimal::from(100);
                    (Some(last_price.clone()), Some(change.with_scale(2)))
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };
            MyCreation {
                creation,
                last_price,
                change_ratio,
            }
        })
        .collect();
    
    #[derive(Serialize)]
    struct MyResponse {
        code: u16,
        list: Vec<MyCreation>,
    }
    HttpResponse::Ok().json(MyResponse { code: 0, list: results })
}

#[derive(Deserialize)]
pub struct ReviewCreationRequest {
    pub creation_id: i32,
    pub approve: bool,
    pub reject_reason: Option<String>, 
}

async fn review_creation(
    _admin: AuthAdmin,
    pool: web::Data<DbPool>,
    req: web::Json<ReviewCreationRequest>,
) -> impl Responder {
    use crate::schema::creations::dsl::*;
    
    let conn = &mut pool.get().expect("Failed to get DB connection");
    let now = Local::now();
    let creation = creations
        .filter(creation_id.eq(req.creation_id))
        .first::<Creation>(conn)
        .optional()
        .expect("DB error while fetching creation");
    let Some(creation) = creation else {
        return HttpResponse::NotFound().json(ErrorResponse { code: 404, message: "创作不存在".into() });
    };
    if creation.review_status.as_deref() != Some("pending") {
        return HttpResponse::BadRequest().json(ErrorResponse { code: 302, message: "该创作不处于待审核状态".into() });
    }

    let target = creations.filter(creation_id.eq(req.creation_id));
    let result = if req.approve {
        diesel::update(target)
            .set((
                review_status.eq("approved"),
                rejected_at.eq::<Option<DateTime<Local>>>(None),
                reject_reason.eq::<Option<String>>(None),
            ))
            .execute(conn)
        } else {
            if req.reject_reason.is_none() {
                return HttpResponse::BadRequest().json(ErrorResponse { code: 205, message: "拒绝时必须填写理由".into() });
            }

            let config: SystemConfig = system_config::table.first(conn).expect("db error");
            let updated: Account = diesel::update(accounts::table.filter(accounts::user_id.eq(creation.creator_id)))
                .set(accounts::balance.eq(accounts::balance + &config.issue_review))
                .get_result(conn)
                .expect("db error");
            let new_log = NewBalanceLog {
                account_id: creation.creator_id,
                amount: config.issue_review.clone(),
                balance_after: updated.balance.unwrap_or(0.into()) + updated.frozen_amount.unwrap_or(0.into()),
                opt_type: "refund".into(),
                memo: Some("发行审核费用退款".into()),
                created_at: Some(Local::now()),
            };
            diesel::insert_into(balance_logs::table)
                .values(&new_log)
                .execute(conn)
                .expect("db error");

            diesel::update(target)
                .set((
                    review_status.eq("rejected"),
                    rejected_at.eq(Some(now)),
                    reject_reason.eq(req.reject_reason.clone()),
                ))
                .execute(conn)
        };

    match result {
        Ok(_) => HttpResponse::Ok().json(ErrorResponse { code: 0, message: "审核处理成功".into() }),
        Err(e) => HttpResponse::InternalServerError().body(format!("数据库错误: {}", e)),
    }
}

async fn list_pending_creations(
    pool: web::Data<DbPool>,
    _admin: AuthAdmin,
) -> impl Responder {
    use crate::schema::creations::dsl::*;
    
    let conn = &mut pool.get().expect("Failed to get DB connection");
    let results = creations
        .filter(review_status.eq("pending"))
        .load::<Creation>(conn);
    
    #[derive(Serialize)]
    struct MyResponse {
        code: u16,
        list: Vec<Creation>,
    }
    match results {
        Ok(list) => HttpResponse::Ok().json(MyResponse { code: 0, list }),
        Err(_) => HttpResponse::InternalServerError().json(ErrorResponse { code: 0, message: "Query failed".into() }),
    }
}

#[get("/get_config")]
async fn get_config(
    pool: web::Data<DbPool>,
) -> impl Responder {
    use crate::schema::system_config::dsl::*;
    
    let conn = &mut pool.get().expect("db error");
    let config = system_config
        .first::<SystemConfig>(conn)
        .expect("db error");
    
    #[derive(Serialize)]
    struct MyResponse {
        code: u16,
        config: SystemConfig,
    }
    HttpResponse::Ok().json(MyResponse { code: 0, config })
}

#[derive(Deserialize)]
struct SetConfigRequest {
    pub trade_fee: BigDecimal,
    pub withdraw_fee: BigDecimal,
    pub vip_trade_fee: BigDecimal,
    pub vip_withdraw_fee: BigDecimal,
    pub issue_review: BigDecimal,
    pub auth_review: BigDecimal,
}

async fn set_config(
    pool: web::Data<DbPool>,
    admin: AuthAdmin,
    req: web::Json<SetConfigRequest>,
) -> impl Responder {
    use crate::schema::system_config::dsl::*;
    let conn = &mut pool.get().expect("db error");
    diesel::update(system_config)
        .set((
            trade_fee.eq(&req.trade_fee),
            withdraw_fee.eq(&req.withdraw_fee),
            vip_trade_fee.eq(&req.vip_trade_fee),
            vip_withdraw_fee.eq(&req.vip_withdraw_fee),
            issue_review.eq(&req.issue_review),
            auth_review.eq(&req.auth_review)
        ))
        .execute(conn)
        .expect("db error");
    HttpResponse::Ok().body(format!("配置设置成功 {}", admin.user_id))
}

#[get("/select_collection_to_boost")]
async fn select_collection_to_boost(
    pool: web::Data<DbPool>,
    auth_user: AuthUser,
) -> impl Responder {
    use crate::schema::creations::dsl::*;
    use crate::schema::collections::dsl::*;
    
    #[derive(Serialize, Queryable)]
    struct SelectToBoostItem {
        collection_id: i32,
        title: String,
        boost: Option<i32>,
    }
    let conn = &mut pool.get().expect("Failed to get DB connection");
    let result = collections
        .inner_join(creations.on(collection_id.eq(creation_id)))
        .filter(creator_id.eq(auth_user.user_id))
        .filter(trade_start_at.is_not_null().and(trade_start_at.lt(Local::now())))
        .select((
            collection_id,
            title,
            boost
        ))
        .load::<SelectToBoostItem>(conn);

    #[derive(Serialize)]
    struct MyResponse {
        code: u16,
        list: Vec<SelectToBoostItem>,
    }
    match result {
        Ok(list) => HttpResponse::Ok().json(MyResponse { code: 0, list }),
        Err(_) => HttpResponse::InternalServerError().json(ErrorResponse { code: 0, message: "Query failed".into() }),
    }
}

#[derive(Deserialize)]
struct PaginationQuery {
    page: Option<i64>,
    page_size: Option<i64>,
    sort_by: Option<String>,
}

#[derive(Serialize, Queryable)]
struct CollectionListItem {
    collection_id: i32,
    title: String,
    cover_image: Option<String>,
    total_supply: i32,
    issue_price: Option<BigDecimal>,
    trade_start_at: Option<DateTime<Local>>,
    last_trade_price: Option<BigDecimal>,
    high_24h: Option<BigDecimal>,
    low_24h: Option<BigDecimal>,
    volume_24h: Option<BigDecimal>,
    count_24h: Option<i32>,
    creator_type: Option<String>,
    is_new: bool,
    price_change_amount: Option<BigDecimal>,         
    price_change_ratio: Option<BigDecimal>, 
    is_hot: bool,
    boost: Option<i32>,
    recommend_score: Option<BigDecimal>,
}

#[get("/recommend_list")]
async fn recommendations (
    pool: web::Data<DbPool>, 
    req: web::Query<PaginationQuery>
) -> impl Responder {
    use crate::schema::collections::dsl::*;
    use crate::schema::creations::dsl::*;
    use crate::schema::accounts::dsl::*;

    let conn = &mut pool.get().expect("couldn't get db connection from pool");
    let page = req.page.unwrap_or(1).max(1);
    let page_size = req.page_size.unwrap_or(10).clamp(1, 100);
    let offset = (page - 1) * page_size;

    let hot_line = collections
        .select(count_24h)
        .filter(count_24h.is_not_null())
        .order(count_24h.desc())
        .offset(2)
        .limit(1)
        .first::<Option<i32>>(conn)
        .expect("db error")
        .unwrap_or(0);

    let mut query = collections
        .inner_join(creations.on(collection_id.eq(creation_id)))
        .inner_join(accounts.on(creator_id.eq(user_id)))
        .select((
            collection_id,
            title,
            cover_image,
            total_supply,
            issue_price,
            trade_start_at,
            last_trade_price,
            high_24h,
            low_24h,
            volume_24h,
            count_24h,
            account_type,
            sql::<Bool>("creations.trade_start_at IS NOT NULL AND now() - creations.trade_start_at <= interval '72 hours'"),
            sql::<Nullable<Numeric>>("collections.last_trade_price - creations.issue_price"),
            sql::<Nullable<Numeric>>("ROUND((collections.last_trade_price - creations.issue_price) / NULLIF(creations.issue_price, 0) * 100, 2)"),
            sql::<Bool>(&format!("count_24h IS NOT NULL AND count_24h >= {}", hot_line)),
            boost,
            recommend_score
        ))
        .filter(count_24h.is_not_null())
        .into_boxed(); 

    if let Some(sort_field) = &req.sort_by {
        match sort_field.as_str() {
            "recommend" => {
                query = query.order_by(recommend_score.desc().nulls_last());
            }
            "change" => {
                let expr = sql::<Nullable<Numeric>>("(collections.last_trade_price - creations.issue_price) / NULLIF(creations.issue_price, 0)");
                query = query.order_by(expr.desc().nulls_last());
            }
            "change_asc" => {
                let expr = sql::<Nullable<Numeric>>("(collections.last_trade_price - creations.issue_price) / NULLIF(creations.issue_price, 0)");
                query = query.order_by(expr.asc().nulls_last());
            }
            "new_online" => {
                query = query.order_by(trade_start_at.desc().nulls_last());
            }
            _ => {
                query = query.order_by(recommend_score.desc().nulls_last());
            }
        }
    } else {
        query = query.order_by(recommend_score.desc().nulls_last());
    }

    let results = query
        .limit(page_size)
        .offset(offset)
        .load::<CollectionListItem>(conn)
        .expect("db error");

    let total_count: i64 = collections
        .filter(count_24h.is_not_null())
        .count()
        .get_result(conn)
        .expect("db error");

    #[derive(Serialize)]
    struct MyResponse {
        code: u16,
        total_count: i64,
        list: Vec<CollectionListItem>,
    }
    HttpResponse::Ok().json(MyResponse { code: 0, total_count, list: results })
}

#[get("/list_collections")]
async fn list_collections(
    pool: web::Data<DbPool>, 
    req: web::Query<PaginationQuery>
) -> actix_web::Result<HttpResponse> {
    use crate::schema::collections::dsl::*;
    use crate::schema::creations::dsl::*;
    use crate::schema::accounts::dsl::*;

    let conn = &mut pool.get().expect("couldn't get db connection from pool");
    let page = req.page.unwrap_or(1).max(1);
    let page_size = req.page_size.unwrap_or(10).clamp(1, 100);
    let offset = (page - 1) * page_size;

    let hot_line = collections
        .select(count_24h)
        .filter(count_24h.is_not_null())
        .order(count_24h.desc())
        .offset(2)
        .limit(1)
        .first::<Option<i32>>(conn)
        .expect("db error")
        .unwrap_or(0);
    
    let mut query = collections
        .inner_join(creations.on(collection_id.eq(creation_id)))
        .inner_join(accounts.on(creator_id.eq(user_id)))
        .select((
            collection_id,
            title,
            cover_image,
            total_supply,
            issue_price,
            trade_start_at,
            last_trade_price,
            high_24h,
            low_24h,
            volume_24h,
            all_time_count,
            account_type,
            sql::<Bool>("creations.trade_start_at IS NOT NULL AND now() - creations.trade_start_at <= interval '72 hours'"),
            sql::<Nullable<Numeric>>("collections.last_trade_price - creations.issue_price"),
            sql::<Nullable<Numeric>>("ROUND((collections.last_trade_price - creations.issue_price) / NULLIF(creations.issue_price, 0) * 100, 2)"),
            sql::<Bool>(&format!("count_24h IS NOT NULL AND count_24h >= {}", hot_line)),
            boost,
            recommend_score
        ))
        .into_boxed(); 
    
    if let Some(sort_field) = &req.sort_by {
        match sort_field.as_str() {
            "title" => {
                query = query.order_by(title.asc());
            }
            "time" => {
                query = query.order_by(issued_at.desc().nulls_last());
            }
            "time_asc" => {
                query = query.order_by(issued_at.asc().nulls_last());
            }
            "price" => {
                query = query.order_by(last_trade_price.desc().nulls_last());
            }
            "price_asc" => {
                query = query.order_by(last_trade_price.asc().nulls_last());
            }
            "change" => {
                let expr = sql::<Nullable<Numeric>>("(collections.last_trade_price - creations.issue_price) / NULLIF(creations.issue_price, 0)");
                query = query.order_by(expr.desc().nulls_last());
            }
            "change_asc" => {
                let expr = sql::<Nullable<Numeric>>("(collections.last_trade_price - creations.issue_price) / NULLIF(creations.issue_price, 0)");
                query = query.order_by(expr.asc().nulls_last());
            }
            _ => {
                query = query.order_by(market_cap.desc().nulls_last());
            }
        }
    } else {
        query = query.order_by(market_cap.desc().nulls_last());
    }

    let results = query
        .limit(page_size)
        .offset(offset)
        .load::<CollectionListItem>(conn)
        .map_err(|_| actix_web::error::ErrorInternalServerError(serde_json::json!({"code": 501, "message": "查询失败"})))?;
    
    let total_count: i64 = collections
        .select(count_star())
        .first(conn)
        .map_err(|_| actix_web::error::ErrorInternalServerError(serde_json::json!({"code": 501, "message": "查询失败"})))?;

    #[derive(Serialize)]
    struct MyResponse {
        code: u16,
        total_count: i64,
        list: Vec<CollectionListItem>,
    }
    Ok(HttpResponse::Ok().json(MyResponse { code: 0, total_count, list: results }))
}

#[derive(QueryableByName, Serialize)]
struct MyCollectionItem {
    #[diesel(sql_type = Integer)]
    collection_id: i32,
    #[diesel(sql_type = BigInt)]
    owned_count: i64,
    #[diesel(sql_type = Text)]
    title: String,
    #[diesel(sql_type = Nullable<Text>)]
    cover_image: Option<String>,
    #[diesel(sql_type = Integer)]
    total_supply: i32,
    #[diesel(sql_type = Nullable<Numeric>)]
    issue_price: Option<BigDecimal>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    issued_at: Option<DateTime<Local>>,
    #[diesel(sql_type = Nullable<Numeric>)]
    last_trade_price: Option<BigDecimal>,
    #[diesel(sql_type = Nullable<Numeric>)]
    price_change_amount: Option<BigDecimal>,
    #[diesel(sql_type = Nullable<Numeric>)]
    price_change_ratio: Option<BigDecimal>,
}

#[get("/my_collections")]
async fn my_collections(
    pool: web::Data<DbPool>,
    auth_user: AuthUser,
) -> actix_web::Result<HttpResponse> {
    let conn = &mut pool.get().map_err(|_| actix_web::error::ErrorInternalServerError("db error"))?;
    let query = r#"
        SELECT
            collections.collection_id,
            COUNT(*) AS owned_count,
            creations.title,
            creations.cover_image,
            creations.total_supply,
            creations.issue_price,
            creations.issued_at,
            collections.last_trade_price,
            (collections.last_trade_price - creations.issue_price) AS price_change_amount,
            ROUND((collections.last_trade_price - creations.issue_price) / NULLIF(creations.issue_price, 0) * 100, 2) AS price_change_ratio
        FROM assets
        INNER JOIN collections ON assets.collection_id = collections.collection_id
        INNER JOIN creations ON collections.collection_id = creations.creation_id
        WHERE assets.owner_id = $1
        GROUP BY 
            collections.collection_id,
            creations.title,
            creations.cover_image,
            creations.total_supply,
            creations.issue_price,
            creations.issued_at,
            collections.last_trade_price
        ORDER BY creations.issued_at DESC
    "#;

    let rows: Vec<MyCollectionItem> = sql_query(query)
        .bind::<Integer, _>(auth_user.user_id)
        .load(conn)
        .map_err(|_| actix_web::error::ErrorInternalServerError(serde_json::json!({"code": 503, "message": "服务器内部错误"})))?;
  
    #[derive(Serialize)]
    struct MyResponse {
        code: u16,
        list: Vec<MyCollectionItem>,
    }
    Ok(HttpResponse::Ok().json(MyResponse { code: 0, list: rows }))
}

#[derive(Deserialize)]
pub struct CollectionRequest {
    pub collection_id: i32,
}

#[derive(QueryableByName, Serialize)]
struct CollectionInfo {
    #[diesel(sql_type = Integer)]
    collection_id: i32,
    #[diesel(sql_type = Text)]
    title: String,
    #[diesel(sql_type = Nullable<Text>)]
    cover_image: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    description: Option<String>,
    #[diesel(sql_type = Integer)]
    creator_id: i32,
    #[diesel(sql_type = Nullable<Text>)]
    nickname: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    avatar: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    account_type: Option<String>,
    #[diesel(sql_type = Integer)]
    total_supply: i32,
    #[diesel(sql_type = Nullable<Numeric>)]
    issue_price: Option<BigDecimal>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    issued_at: Option<DateTime<Local>>,
    #[diesel(sql_type = Nullable<Text>)]
    contract_address: Option<String>,
    #[diesel(sql_type = Nullable<Numeric>)]
    last_trade_price: Option<BigDecimal>,
    #[diesel(sql_type = Nullable<Numeric>)]
    high_24h: Option<BigDecimal>,
    #[diesel(sql_type = Nullable<Numeric>)]
    low_24h: Option<BigDecimal>,
    #[diesel(sql_type = Nullable<Numeric>)]
    volume_24h: Option<BigDecimal>,
    #[diesel(sql_type = Nullable<Integer>)]
    count_24h: Option<i32>,
    #[diesel(sql_type = Nullable<Numeric>)]
    all_time_low: Option<BigDecimal>,
    #[diesel(sql_type = Nullable<Numeric>)]
    all_time_high: Option<BigDecimal>,
    #[diesel(sql_type = Nullable<Numeric>)]
    all_time_volume: Option<BigDecimal>,
    #[diesel(sql_type = Nullable<Integer>)]
    all_time_count: Option<i32>,
    #[diesel(sql_type = Nullable<Numeric>)]
    market_cap: Option<BigDecimal>,
    #[diesel(sql_type = Nullable<Numeric>)]
    price_change_amount: Option<BigDecimal>,
    #[diesel(sql_type = Nullable<Numeric>)]
    price_change_ratio: Option<BigDecimal>,
    #[diesel(sql_type = BigInt)]
    market_cap_rank: i64,
    #[diesel(sql_type = Bool)]
    is_new: bool,
    #[diesel(sql_type = Bool)]
    is_hot: bool,
    #[diesel(sql_type = Nullable<Integer>)]
    boost: Option<i32>,
    #[diesel(sql_type = BigInt)]
    recommend_rank: i64,
}

#[get("/collection_info")]
async fn collection_info(
    pool: web::Data<DbPool>,
    req: web::Query<CollectionRequest>
) -> actix_web::Result<HttpResponse> {
    let conn = &mut pool.get().map_err(|_| actix_web::error::ErrorInternalServerError("db error"))?;
    let query = r#"
        WITH ranked_collections AS (
            SELECT 
                c.*,
                RANK() OVER (ORDER BY c.market_cap DESC NULLS LAST) AS market_cap_rank,
                RANK() OVER (ORDER BY c.recommend_score DESC NULLS LAST) AS recommend_rank,
                (RANK() OVER (ORDER BY count_24h DESC NULLS LAST) <= 3) AS is_hot 
            FROM collections c
        )
        SELECT
            rc.collection_id,
            creations.title,
            creations.cover_image,
            creations.description,
            creations.creator_id,
            accounts.nickname,
            accounts.avatar,
            accounts.account_type,
            creations.total_supply,
            creations.issue_price,
            creations.issued_at,
            creations.contract_address,
            rc.last_trade_price,
            rc.high_24h,
            rc.low_24h,
            rc.volume_24h,
            rc.count_24h,
            rc.all_time_low,
            rc.all_time_high,
            rc.all_time_volume,
            rc.all_time_count,
            rc.market_cap,
            (rc.last_trade_price - creations.issue_price) AS price_change_amount,
            ROUND((rc.last_trade_price - creations.issue_price) / NULLIF(creations.issue_price, 0) * 100, 2) AS price_change_ratio,
            rc.market_cap_rank,
            CASE 
                WHEN creations.issued_at IS NOT NULL AND creations.issued_at > NOW() - INTERVAL '72 hours' 
                THEN true 
                ELSE false 
            END AS is_new,
            rc.is_hot,
            rc.boost,
            rc.recommend_rank 
        FROM ranked_collections rc
        INNER JOIN creations ON rc.collection_id = creations.creation_id
        INNER JOIN accounts ON creations.creator_id = accounts.user_id
        WHERE rc.collection_id = $1
    "#;

    let result: CollectionInfo = sql_query(query)
        .bind::<Integer, _>(req.collection_id)
        .get_result(conn)
        .map_err(|_| actix_web::error::ErrorInternalServerError(serde_json::json!({"code": 404, "message": "没找到这个集合"})))?;
  
    #[derive(Serialize)]
    struct MyResponse {
        code: u16,
        collection: CollectionInfo,
    }
    Ok(HttpResponse::Ok().json(MyResponse { code: 0, collection: result }))
}

#[derive(QueryableByName, Serialize)]
struct CollectionHolder {
    #[diesel(sql_type = Integer)]
    user_id: i32,
    #[diesel(sql_type = Text)]
    nickname: String,
    #[diesel(sql_type = Text)]
    avatar: String,
    #[diesel(sql_type = BigInt)]
    owned_count: i64,
    #[diesel(sql_type = Numeric)]
    ownership_ratio: BigDecimal,
}

#[get("/collection_holders")]
async fn collection_holders(
    pool: web::Data<DbPool>, 
    req: web::Query<CollectionRequest>
) -> actix_web::Result<HttpResponse> {
    let conn = &mut pool.get().map_err(|_| actix_web::error::ErrorInternalServerError("db error"))?;
    let query = r#"
        SELECT
            accounts.user_id,
            accounts.nickname,
            accounts.avatar,
            COUNT(*) AS owned_count,
            ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER(), 2) AS ownership_ratio 
        FROM assets 
        JOIN accounts ON assets.owner_id = accounts.user_id 
        WHERE assets.collection_id = $1
        GROUP BY accounts.user_id, accounts.nickname, accounts.avatar 
        ORDER BY owned_count DESC
    "#;

    let holders: Vec<CollectionHolder> = sql_query(query)
        .bind::<Integer, _>(req.collection_id)
        .load(conn)
        .map_err(|_| actix_web::error::ErrorInternalServerError(serde_json::json!({"code": 503, "message": "服务器内部错误"})))?;
        
    #[derive(Serialize)]
    struct MyResponse {
        code: u16,
        holders: Vec<CollectionHolder>,
    }
    Ok(HttpResponse::Ok().json(MyResponse { code: 0, holders }))
}

#[derive(Deserialize)]
pub struct PlaceOrderRequest {
    pub side: String,
    pub collection_id: i32,    
    pub serial_number: Option<String>,
    pub price: BigDecimal,
}

enum PlaceOutcome {
    Success(TradeOrder),
    Failure(ErrorResponse),
}

#[post("/place_order")]
async fn place_order(
    auth_user: AuthUser,
    pool: web::Data<DbPool>,
    req: web::Json<PlaceOrderRequest>,
) -> impl Responder {
    let conn = &mut pool.get().expect("db error");
    let req = req.into_inner();
    let maker_id = auth_user.user_id;

    let result = conn.transaction::<_, diesel::result::Error, _>(|conn| {
        let mut user: Account = accounts::table
            .filter(accounts::user_id.eq(maker_id))
            .first(conn)?;
        let config: SystemConfig = system_config::table.first(conn)?;
        let fee_percentage = if user.is_vip == Some(true) { config.vip_trade_fee } else { config.trade_fee };
        let fee = (&req.price * &fee_percentage / BigDecimal::from(100)).with_scale(2);
        if user.balance.as_ref().map_or(true, |v| v < &fee) {
            return Ok(PlaceOutcome::Failure(ErrorResponse { code: 310, message: format!("挂单要付挂单金额 {}% 的手续费，你的余额不足，请充值。", fee_percentage) }));
        }
        user.balance = user.balance.map(|v| v - &fee);

        match req.side.as_str() {
            "sell" => {
                let Some(serial_number) = req.serial_number.as_ref()  else {
                    return Ok(PlaceOutcome::Failure(ErrorResponse { code: 301, message: "卖方必须提供资产编号".into() }));
                };            
                let asset = assets::table
                    .filter(assets::collection_id.eq(req.collection_id).and(assets::serial_number.eq(serial_number)))
                    .first::<Asset>(conn)
                    .optional()?;
                let Some(asset) = asset else {
                    return Ok(PlaceOutcome::Failure(ErrorResponse { code: 302, message: "编号对应的资产不存在".into() }));
                };
                if asset.owner_id != maker_id {
                    return Ok(PlaceOutcome::Failure(ErrorResponse { code: 303, message: "卖方并不拥有编号对应的资产".into() }));
                }
                if matches!(asset.is_locked, Some(true)) {
                    return Ok(PlaceOutcome::Failure(ErrorResponse { code: 304, message: "资产已被锁定，不能再次下单".into() }));
                }

                let is_tradable = collections::table
                    .filter(collections::collection_id.eq(req.collection_id))
                    .select(collections::is_tradable)
                    .first::<Option<bool>>(conn)?;
                if matches!(is_tradable, Some(false)) {
                    return Ok(PlaceOutcome::Failure(ErrorResponse { code: 305, message: "资产系列不可交易".into() }));
                }

                diesel::update(assets::table.filter(assets::asset_id.eq(asset.asset_id)))
                    .set(assets::is_locked.eq(true))
                    .execute(conn)?;
            }
            "buy" => {            
                let collection = collections::table
                    .filter(collections::collection_id.eq(req.collection_id))
                    .first::<Collection>(conn)
                    .optional()?;
                let Some(collection) = collection else {
                    return Ok(PlaceOutcome::Failure(ErrorResponse { code: 306, message: "资产系列不存在".into() }));
                };
                if matches!(collection.is_tradable, Some(false)) {
                    return Ok(PlaceOutcome::Failure(ErrorResponse { code: 305, message: "资产系列不可交易".into() }));
                }

                if let Some(ref sn) = req.serial_number {
                    let asset = assets::table
                        .filter(assets::collection_id.eq(req.collection_id).and(assets::serial_number.eq(sn)))
                        .first::<Asset>(conn)
                        .optional()?;
                    let Some(asset) = asset else {
                        return Ok(PlaceOutcome::Failure(ErrorResponse { code: 302, message: "编号对应的资产不存在".into() }));
                    };
                    if asset.owner_id == maker_id {
                        return Ok(PlaceOutcome::Failure(ErrorResponse { code: 307, message: "你已拥有编号对应的资产".into() }));
                    }
                }

                if user.balance.as_ref().map_or(true, |v| v < &req.price) {
                    return Ok(PlaceOutcome::Failure(ErrorResponse { code: 309, message: "挂买单要锁定出价，你的余额不足你的出价，请充值。".into() }));
                }
                diesel::update(accounts::table.filter(accounts::user_id.eq(maker_id)))
                    .set((
                        accounts::balance.eq(accounts::balance - &req.price),
                        accounts::frozen_amount.eq(accounts::frozen_amount + &req.price)
                    ))
                    .execute(conn)?;
            }
            _ => return Ok(PlaceOutcome::Failure(ErrorResponse { code: 308, message: "无效的交易方向 (buy/sell)".into() })),
        };

        diesel::update(accounts::table.filter(accounts::user_id.eq(maker_id)))
            .set(accounts::balance.eq(accounts::balance - &fee))
            .execute(conn)?;
        let new_log = NewBalanceLog {
            account_id: maker_id,
            amount: -fee.clone(),
            balance_after: user.balance.unwrap_or(0.into()) + user.frozen_amount.unwrap_or(0.into()),
            opt_type: "fee".into(),
            memo: Some("交易手续费".into()),
            created_at: Some(Local::now()),
        };
        diesel::insert_into(balance_logs::table)
            .values(&new_log)
            .execute(conn)?;

        let new_order = NewTradeOrder {
            maker_id,
            taker_id: None,
            side: req.side,
            collection_id: req.collection_id,
            serial_number: req.serial_number,
            price: req.price,
            status: Some("open".into()),
            created_at: Some(Local::now()),
            filled_at: None,
            fee,
        };
        let inserted_order: TradeOrder = diesel::insert_into(trade_orders::table)
            .values(&new_order)
            .get_result(conn)?;
        
        Ok(PlaceOutcome::Success(inserted_order))
    });
    #[derive(Serialize)]
    struct SuccessResponse {
        code: u16,
        order: TradeOrder,
    }
    match result {
        Ok(PlaceOutcome::Success(order)) =>  HttpResponse::Ok().json(SuccessResponse { code: 0, order }),
        Ok(PlaceOutcome::Failure(response)) => HttpResponse::Ok().json(response),
        Err(_) => HttpResponse::InternalServerError().json(ErrorResponse { code: 503, message: "数据库错误".into() }),
    }
}

#[derive(Deserialize)]
pub struct CancelOrderRequest {
    pub order_id: i32,
}

enum CancelOutcome {
    Success,
    Failure(ErrorResponse),
}

#[post("/cancel_order")]
async fn cancel_order(
    auth_user: AuthUser,
    pool: web::Data<DbPool>,
    req: web::Json<CancelOrderRequest>,
) -> impl Responder {
    let conn = &mut pool.get().expect("db error");
    let req = req.into_inner();
    let result = conn.transaction::<_, diesel::result::Error, _>(|conn| {
        let order = trade_orders::table
            .filter(trade_orders::order_id.eq(req.order_id))
            .first::<TradeOrder>(conn)
            .optional()?;
        let Some(order) = order else {
            return Ok(CancelOutcome::Failure(ErrorResponse { code: 310, message: "无效的订单号".into() }));
        };
        if order.maker_id != auth_user.user_id {
            return Ok(CancelOutcome::Failure(ErrorResponse { code: 311, message: "权限错误，你不是挂单人".into() }));
        }
        if order.status.as_deref() != Some("open") {
            return Ok(CancelOutcome::Failure(ErrorResponse { code: 312, message: "订单已成交或已撤单，不能再撤单".into() }));
        }

        if order.side.as_str() == "sell" {
            diesel::update(assets::table
                .filter(assets::collection_id.eq(order.collection_id).and(assets::serial_number.eq(&order.serial_number))))
                .set(assets::is_locked.eq(false))
                .execute(conn)?;
        } else if order.side.as_str() == "buy" {
            diesel::update(accounts::table.filter(accounts::user_id.eq(auth_user.user_id)))
                .set((
                    accounts::balance.eq(accounts::balance + &order.price),
                    accounts::frozen_amount.eq(accounts::frozen_amount - &order.price)
                ))
                .execute(conn)?;
        }
        diesel::update(trade_orders::table.filter(trade_orders::order_id.eq(req.order_id)))
            .set(trade_orders::status.eq("cancelled"))
            .execute(conn)?;

        let (balance, frozen): (Option<BigDecimal>, Option<BigDecimal>) = diesel::update(accounts::table.filter(accounts::user_id.eq(auth_user.user_id)))
            .set(accounts::balance.eq(accounts::balance + &order.fee))
            .returning((accounts::balance, accounts::frozen_amount))
            .get_result(conn)?;

        let new_log = NewBalanceLog {
            account_id: order.maker_id,
            amount: order.fee,
            balance_after: balance.unwrap_or(0.into()) + frozen.unwrap_or(0.into()),
            opt_type: "refund".into(),
            memo: Some("交易手续费退款".into()),
            created_at: Some(Local::now()),
        };
        diesel::insert_into(balance_logs::table)
            .values(&new_log)
            .execute(conn)?;

        Ok(CancelOutcome::Success)
    });
    match result {
        Ok(CancelOutcome::Success) => HttpResponse::Ok().json(ErrorResponse { code: 0, message: "撤单成功".into() }),
        Ok(CancelOutcome::Failure(response)) => HttpResponse::Ok().json(response),
        Err(_) => HttpResponse::InternalServerError().json(ErrorResponse { code: 503, message: "数据库错误".into() }),
    }    
}

#[derive(Deserialize)]
pub struct MatchOrderRequest {
    pub order_id: i32,
}

enum MatchOutcome {
    Success,
    Failure(ErrorResponse),
}

#[post("/match_order")]
async fn match_order(
    auth_user: AuthUser,
    pool: web::Data<DbPool>,
    req: web::Json<MatchOrderRequest>,
) -> impl Responder {
    let conn = &mut pool.get().expect("db error");
    let req = req.into_inner();
    let taker_id = auth_user.user_id;
    let result = conn.transaction::<_, diesel::result::Error, _>(|conn| {
        let now = Local::now();
        let order = trade_orders::table
            .filter(trade_orders::order_id.eq(req.order_id))
            .first::<TradeOrder>(conn)
            .optional()?;
        let Some(order) = order else {
            return Ok(MatchOutcome::Failure(ErrorResponse { code: 310, message: "无效的订单号".into() }));
        };    
        if order.maker_id == taker_id {
            return Ok(MatchOutcome::Failure(ErrorResponse { code: 320, message: "挂单人和成交人不能是同一个人".into() }));
        }
        if order.status.as_deref() != Some("open") {
            return Ok(MatchOutcome::Failure(ErrorResponse { code: 321, message: "订单已成交或已撤单，不能再成交".into() }));
        }

        let mut user: Account = accounts::table
            .filter(accounts::user_id.eq(taker_id))
            .first(conn)?;
        let config: SystemConfig = system_config::table.first(conn)?;
        let fee_percentage = if user.is_vip == Some(true) { config.vip_trade_fee } else { config.trade_fee };
        let fee = (&order.price * &fee_percentage / BigDecimal::from(100)).with_scale(2);
        if user.balance.as_ref().map_or(true, |v| v < &fee) {
            return Ok(MatchOutcome::Failure(ErrorResponse { code: 322, message: format!("成交要付订单金额 {}% 的手续费，你的余额不足，请充值。", fee_percentage) }));
        }
        user.balance = user.balance.map(|v| v - &fee);
        
        match order.side.as_str() {
            "buy" => {
                let asset_opt = if let Some(serial) = order.serial_number.as_ref() {
                    assets::table
                        .filter(assets::collection_id.eq(order.collection_id))
                        .filter(assets::serial_number.eq(serial))
                        .filter(assets::owner_id.eq(taker_id))
                        .filter(assets::is_locked.eq(false))
                        .first::<Asset>(conn)
                        .optional()?
                } else {
                    assets::table
                        .filter(assets::collection_id.eq(order.collection_id))
                        .filter(assets::owner_id.eq(taker_id))
                        .filter(assets::is_locked.eq(false))
                        .first::<Asset>(conn)
                        .optional()?
                };
                let Some(asset) = asset_opt else {
                    return Ok(MatchOutcome::Failure(ErrorResponse { code: 323, message: "你没有相匹配的资产，或者匹配的资产在其他挂单中被锁定，请先去撤单。".into() }));
                };
                
                diesel::update(assets::table.filter(assets::asset_id.eq(asset.asset_id)))
                    .set((
                        assets::owner_id.eq(order.maker_id),
                        assets::source_type.eq("trade"),
                        assets::last_price.eq(&order.price),
                        assets::updated_at.eq(now),
                    ))
                    .execute(conn)?; 

                let updated: Account = diesel::update(accounts::table.filter(accounts::user_id.eq(taker_id)))
                    .set(accounts::balance.eq(accounts::balance + &order.price))
                    .get_result(conn)?;
                let new_log = NewBalanceLog {
                    account_id: taker_id,
                    amount: order.price.clone(),
                    balance_after: updated.balance.unwrap_or(0.into()) + updated.frozen_amount.unwrap_or(0.into()),
                    opt_type: "sell".into(),
                    memo: Some("卖出".into()),
                    created_at: Some(Local::now()),
                };
                diesel::insert_into(balance_logs::table)
                    .values(&new_log)
                    .execute(conn)?;

                let updated: Account = diesel::update(accounts::table.filter(accounts::user_id.eq(order.maker_id)))
                    .set(accounts::frozen_amount.eq(accounts::frozen_amount - &order.price))
                    .get_result(conn)?;
                let new_log = NewBalanceLog {
                    account_id: order.maker_id,
                    amount: -order.price.clone(),
                    balance_after: updated.balance.unwrap_or(0.into()) + updated.frozen_amount.unwrap_or(0.into()),
                    opt_type: "buy".into(),
                    memo: Some("买入".into()),
                    created_at: Some(Local::now()),
                };
                diesel::insert_into(balance_logs::table)
                    .values(&new_log)
                    .execute(conn)?;
            }
            "sell" => {
                if user.balance.as_ref().map_or(true, |v| v < &order.price) {
                    return Ok(MatchOutcome::Failure(ErrorResponse { code: 324, message: "余额不足无法成交，请充值。".into() }));
                }

                let asset = assets::table
                    .filter(assets::collection_id.eq(order.collection_id))
                    .filter(assets::serial_number.eq(order.serial_number.clone()))
                    .filter(assets::is_locked.eq(true))
                    .filter(assets::owner_id.eq(order.maker_id))
                    .first::<Asset>(conn)?;

                diesel::update(assets::table.filter(assets::asset_id.eq(asset.asset_id)))
                    .set((
                        assets::owner_id.eq(taker_id),
                        assets::source_type.eq("trade"),
                        assets::is_locked.eq(false),
                        assets::last_price.eq(&order.price),
                        assets::updated_at.eq(now),
                    ))
                    .execute(conn)?;
                
                let updated: Account = diesel::update(accounts::table.filter(accounts::user_id.eq(taker_id)))
                    .set(accounts::balance.eq(accounts::balance - &order.price))
                    .get_result(conn)?;
                let new_log = NewBalanceLog {
                    account_id: taker_id,
                    amount: -order.price.clone(),
                    balance_after: updated.balance.unwrap_or(0.into()) + updated.frozen_amount.unwrap_or(0.into()),
                    opt_type: "buy".into(),
                    memo: Some("买入".into()),
                    created_at: Some(Local::now()),
                };
                diesel::insert_into(balance_logs::table)
                    .values(&new_log)
                    .execute(conn)?;

                let updated: Account = diesel::update(accounts::table.filter(accounts::user_id.eq(order.maker_id)))
                    .set(accounts::balance.eq(accounts::balance + &order.price))
                    .get_result(conn)?;
                let new_log = NewBalanceLog {
                    account_id: order.maker_id,
                    amount: order.price.clone(),
                    balance_after: updated.balance.unwrap_or(0.into()) + updated.frozen_amount.unwrap_or(0.into()),
                    opt_type: "sell".into(),
                    memo: Some("卖出".into()),
                    created_at: Some(Local::now()),
                };
                diesel::insert_into(balance_logs::table)
                    .values(&new_log)
                    .execute(conn)?;
            }
            _ => return Ok(MatchOutcome::Failure(ErrorResponse { code: 308, message: "无效的交易方向 (buy/sell)".into() })),
        }

        let updated: Account = diesel::update(accounts::table.filter(accounts::user_id.eq(taker_id)))
            .set(accounts::balance.eq(accounts::balance - &fee))
            .get_result(conn)?;
        let new_log = NewBalanceLog {
            account_id: taker_id,
            amount: -fee.clone(),
            balance_after: updated.balance.unwrap_or(0.into()) + updated.frozen_amount.unwrap_or(0.into()),
            opt_type: "fee".into(),
            memo: Some("交易手续费".into()),
            created_at: Some(Local::now()),
        };
        diesel::insert_into(balance_logs::table)
            .values(&new_log)
            .execute(conn)?;
            
        diesel::update(trade_orders::table.filter(trade_orders::order_id.eq(order.order_id)))
            .set((
                trade_orders::status.eq("filled"),
                trade_orders::taker_id.eq(taker_id),
                trade_orders::filled_at.eq(now),
            ))
            .execute(conn)?;
        
        let (col, supply): (Collection, i32) = collections::table
            .inner_join(creations::table.on(creations::creation_id.eq(collections::collection_id)))
            .filter(collections::collection_id.eq(order.collection_id))
            .select((collections::all_columns, creations::total_supply))
            .first(conn)?;
        let price = order.price;
        let high = col.high_24h.as_ref();
        let low = col.low_24h.as_ref();
        let ath = col.all_time_high.as_ref();
        let atl = col.all_time_low.as_ref();
        let zero = BigDecimal::from(0);
        let market = &price * BigDecimal::from(supply);
        diesel::update(collections::table.filter(collections::collection_id.eq(order.collection_id)))
            .set((
                collections::last_trade_price.eq(&price),
                collections::high_24h.eq(if high.map_or(true, |h| &price > h) { Some(price.clone()) } else { col.high_24h }),
                collections::low_24h.eq(if low.map_or(true, |l| &price < l) { Some(price.clone()) } else { col.low_24h }),
                collections::volume_24h.eq(col.volume_24h.unwrap_or(zero.clone()) + &price),
                collections::count_24h.eq(col.count_24h.unwrap_or(0) + 1),
                collections::all_time_high.eq(if ath.map_or(true, |h| &price > h) { Some(price.clone()) } else { col.all_time_high }),
                collections::all_time_low.eq(if atl.map_or(true, |l| &price < l) { Some(price.clone()) } else { col.all_time_low }),
                collections::all_time_volume.eq(col.all_time_volume.unwrap_or(zero) + &price),
                collections::all_time_count.eq(col.all_time_count.unwrap_or(0) + 1),
                collections::market_cap.eq(market),
                collections::updated_at.eq(now),
            ))
            .execute(conn)?;
        
        for interval in [1, 4, 12, 24] {
            let start_time = truncate_to_interval(now, interval);
            upsert_kline_data(conn, order.collection_id, interval, start_time, price.clone())?;
        }

        Ok(MatchOutcome::Success)
    });
    match result {
        Ok(MatchOutcome::Success) => HttpResponse::Ok().json(ErrorResponse { code: 0, message: "完美成交！".into() }),
        Ok(MatchOutcome::Failure(response)) => HttpResponse::Ok().json(response),
        Err(_) => HttpResponse::InternalServerError().json(ErrorResponse { code: 503, message: "数据库错误".into() }),
    }
}

fn truncate_to_interval(now: DateTime<Local>, interval: i32) -> DateTime<Local> {
    let naive = now.naive_local();
    let base = match interval {
        1 => naive.date().and_hms_opt(naive.hour(), 0, 0).unwrap(),
        4 => {
            let hour = (naive.hour() / 4) * 4;
            naive.date().and_hms_opt(hour, 0, 0).unwrap()
        },
        12 => {
            let hour = if naive.hour() < 12 { 0 } else { 12 };
            naive.date().and_hms_opt(hour, 0, 0).unwrap()
        },
        24 => naive.date().and_hms_opt(0, 0, 0).unwrap(),
        _ => naive.date().and_hms_opt(naive.hour(), 0, 0).unwrap(),
    };
    Local.from_local_datetime(&base).unwrap()
}

fn upsert_kline_data(
    conn: &mut PgConnection,
    collection_id: i32,
    interval: i32,
    timestamp: DateTime<Local>,
    price: BigDecimal, 
) -> QueryResult<usize> {
    sql_query(r#"
        INSERT INTO kline_data (
            collection_id, interval, timestamp,
            close_price, high_price, low_price, trade_volume, trade_count
        )
        VALUES ($1, $2, $3, $4, $4, $4, $4, 1)
        ON CONFLICT (collection_id, interval, timestamp)
        DO UPDATE SET
            close_price = EXCLUDED.close_price,
            high_price = GREATEST(kline_data.high_price, EXCLUDED.high_price),
            low_price = LEAST(kline_data.low_price, EXCLUDED.low_price),
            trade_volume = kline_data.trade_volume + EXCLUDED.trade_volume,
            trade_count = kline_data.trade_count + 1
    "#)
    .bind::<Integer, _>(collection_id)
    .bind::<Integer, _>(interval)
    .bind::<Timestamptz, _>(timestamp)
    .bind::<Numeric, _>(price)
    .execute(conn)
}


#[derive(Deserialize)]
pub struct KlineByCollectionQuery {
    pub collection_id: i32,
    pub interval: i32,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

#[get("/kline_data_by_collection")]
async fn kline_data_by_collection(
    pool: web::Data<DbPool>,
    query: web::Query<KlineByCollectionQuery>,
) -> impl Responder {
    use crate::schema::kline_data::dsl::*;

    let conn = &mut pool.get().expect("db error");
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(120).clamp(1, 1200);
    let offset = (page - 1) * page_size;
    
    let results = kline_data
        .filter(collection_id.eq(query.collection_id).and(interval.eq(query.interval)))
        .order(timestamp.desc())
        .offset(offset)
        .limit(page_size)
        .load::<KlineData>(conn)
        .expect("db error");
    
    let total_count: i64 = kline_data
        .filter(collection_id.eq(query.collection_id).and(interval.eq(query.interval)))
        .count()
        .get_result(conn)
        .expect("db error");

    #[derive(Serialize)]
    struct MyResponse {
        code: u16,
        total_count: i64,
        list: Vec<KlineData>,
    }
    HttpResponse::Ok().json(MyResponse { code: 0, total_count, list: results })
}

#[derive(Deserialize)]
pub struct OrdersByCollectionQuery {
    pub collection_id: i32,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

#[get("/filled_orders_by_collection")]
async fn filled_orders_by_collection(
    pool: web::Data<DbPool>,
    query: web::Query<OrdersByCollectionQuery>,
) -> impl Responder {
    use crate::schema::trade_orders::dsl::*;

    let conn = &mut pool.get().expect("db error");
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(100).clamp(1, 100);
    let offset = (page - 1) * page_size;
    
    let results = trade_orders
        .filter(collection_id.eq(query.collection_id))
        .filter(status.eq("filled"))
        .order(filled_at.desc().nulls_last())
        .offset(offset)
        .limit(page_size)
        .load::<TradeOrder>(conn)
        .expect("db error");
    
    let total_count: i64 = trade_orders
        .filter(collection_id.eq(query.collection_id))
        .filter(status.eq("filled"))
        .count()
        .get_result(conn)
        .expect("db error");

    #[derive(Serialize)]
    struct MyResponse {
        code: u16,
        total_count: i64,
        list: Vec<TradeOrder>,
    }
    HttpResponse::Ok().json(MyResponse { code: 0, total_count, list: results })
}

#[get("/open_orders_by_collection")]
async fn open_orders_by_collection(
    pool: web::Data<DbPool>,
    query: web::Query<OrdersByCollectionQuery>,
) -> impl Responder {
    use crate::schema::trade_orders::dsl::*;

    let conn = &mut pool.get().expect("db error");
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(100).clamp(1, 100);
    let offset = (page - 1) * page_size;
    
    let results = trade_orders
        .filter(collection_id.eq(query.collection_id))
        .filter(status.eq("open"))
        .order(order_id.desc())
        .offset(offset)
        .limit(page_size)
        .load::<TradeOrder>(conn)
        .expect("db error");
    
    let total_count: i64 = trade_orders
        .filter(collection_id.eq(query.collection_id))
        .filter(status.eq("open"))
        .count()
        .get_result(conn)
        .expect("db error");

    #[derive(Serialize)]
    struct MyResponse {
        code: u16,
        total_count: i64,
        list: Vec<TradeOrder>,
    }
    HttpResponse::Ok().json(MyResponse { code: 0, total_count, list: results })
}

#[get("/my_open_orders_by_collection")]
async fn my_open_orders_by_collection(
    auth_user: AuthUser,
    pool: web::Data<DbPool>,
    query: web::Query<OrdersByCollectionQuery>,
) -> impl Responder {
    use crate::schema::trade_orders::dsl::*;

    let conn = &mut pool.get().expect("db error");
    let results = trade_orders
        .filter(collection_id.eq(query.collection_id))
        .filter(maker_id.eq(auth_user.user_id))
        .filter(status.eq("open"))
        .order(order_id.desc())
        .load::<TradeOrder>(conn)
        .expect("db error");
    
    #[derive(Serialize)]
    struct MyResponse {
        code: u16,
        list: Vec<TradeOrder>,
    }
    HttpResponse::Ok().json(MyResponse { code: 0,  list: results })
}

#[derive(Deserialize)]
pub struct TradeHistoryQuery {
    pub status: String,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

#[derive(Queryable, Serialize)]
struct TradeHistory {
    #[serde(flatten)]
    order: TradeOrder,
    title: String,
    cover_image: Option<String>,
}

#[get("/my_trade_history")]
async fn my_trade_history(
    auth_user: AuthUser,
    pool: web::Data<DbPool>,
    req: web::Query<TradeHistoryQuery>,
) -> impl Responder {
    use crate::schema::trade_orders::dsl::*;
    use crate::schema::creations::dsl::*;
    
    let conn = &mut pool.get().expect("db error");
    let page = req.page.unwrap_or(1).max(1);
    let page_size = req.page_size.unwrap_or(100).clamp(1, 100);
    let offset = (page - 1) * page_size;
    let user_id = auth_user.user_id;
    
    let mut query = trade_orders
        .inner_join(creations.on(creation_id.eq(collection_id)))
        .filter(maker_id.eq(user_id).or(taker_id.eq(user_id)))
        .into_boxed();
    match req.status.as_str() {
        "all" => query = query.filter(status.ne("cancelled")),
        "open" => query = query.filter(status.eq("open")),
        "filled" => query = query.filter(status.eq("filled")),
        _ => query = query.filter(status.ne("cancelled")),
    }
    let results = query
        .select((
            trade_orders::all_columns(),
            title,
            cover_image
        ))
        .order(order_id.desc())
        .offset(offset)
        .limit(page_size)
        .load::<TradeHistory>(conn)
        .expect("db error");
    
    let mut query2 = trade_orders
        .filter(maker_id.eq(user_id).or(taker_id.eq(user_id)))
        .into_boxed();
    match req.status.as_str() {
        "all" => query2 = query2.filter(status.ne("cancelled")),
        "open" => query2 = query2.filter(status.eq("open")),
        "filled" => query2 = query2.filter(status.eq("filled")),
        _ => query2 = query2.filter(status.ne("cancelled")),
    }   
    let total_count: i64 = query2
        .count()
        .get_result(conn)
        .expect("db error");

    #[derive(Serialize)]
    struct MyResponse {
        code: u16,
        total_count: i64,
        list: Vec<TradeHistory>,
    }
    HttpResponse::Ok().json(MyResponse { code: 0, total_count, list: results })
}

#[derive(Deserialize)]
pub struct CollectionTradeHistoryQuery {
    pub collection_id: i32,
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum HistoryItem {
    Order(TradeOrder),
    Transfer(Transfer),
}

impl HistoryItem {
    fn get_time(&self) -> Option<DateTime<Local>> {
        match self {
            HistoryItem::Order(order) => order.filled_at,
            HistoryItem::Transfer(trans) => trans.created_at,
        }
    }
}

#[get("/my_trade_history_by_collection")]
async fn my_trade_history_by_collection(
    auth_user: AuthUser,
    pool: web::Data<DbPool>,
    req: web::Query<CollectionTradeHistoryQuery>,
) -> impl Responder {
    use crate::schema::trade_orders::dsl::*;
    
    let conn = &mut pool.get().expect("db error");
    let user_id = auth_user.user_id;
    let col: Collection = collections::table
        .filter(collections::collection_id.eq(req.collection_id))
        .first(conn)
        .expect("db error");
    let total_count: i64 = assets::table
        .filter(assets::owner_id.eq(user_id))
        .filter(assets::collection_id.eq(req.collection_id))
        .count()
        .get_result(conn)
        .expect("db error");
    let estimated_asset = if let Some(last_price) = col.last_trade_price.as_ref() {
        last_price * BigDecimal::from(total_count)
    } else {
        BigDecimal::from(0)
    };
    let (today_pnl, today_pnl_ratio) = match col.yesterday_price.as_ref() {
        Some(y_price) if *y_price != BigDecimal::from(0) => {
            let y_asset = y_price * BigDecimal::from(total_count);
            let pol = &estimated_asset - &y_asset;
            let ratio = &pol / &y_asset * BigDecimal::from(100);
            (pol.with_scale(2), ratio.with_scale(2))
        }
        _ => (BigDecimal::from(0), BigDecimal::from(0))
    };
    
    let mut orders: Vec<TradeOrder> = trade_orders
        .filter(collection_id.eq(req.collection_id))
        .filter(status.eq("filled"))
        .filter(maker_id.eq(user_id).or(taker_id.eq(user_id)))
        .order(order_id.desc())
        .load(conn)
        .expect("db error");
    for order in orders.iter_mut() {
        match order.side.as_str() {
            "buy" if order.taker_id == Some(user_id) => {
                order.side = "sell".to_string();
            }
            "sell" if order.taker_id == Some(user_id) => {
                order.side = "buy".to_string();
            }
             _ => {}
        }
    }
    let mut trans: Vec<Transfer> = transfers::table
        .filter(transfers::collection_id.eq(req.collection_id))
        .filter(transfers::sender_id.eq(user_id))
        .order(transfers::transfer_id.desc())
        .load(conn)
        .expect("db error");
    if let Some(last_price) = col.last_trade_price.as_ref() {
        for tran in trans.iter_mut() {
            tran.estimated_value = tran.quantity.map(|q| BigDecimal::from(q) * last_price.clone());
        }
    }

    let mut combined: Vec<HistoryItem> = Vec::new();
    combined.extend(orders.into_iter().map(HistoryItem::Order));
    combined.extend(trans.into_iter().map(HistoryItem::Transfer));
    combined.sort_by(|a, b| b.get_time().cmp(&a.get_time()));
    
    #[derive(Serialize)]
    struct MyResponse {
        code: u16,
        estimated_asset: BigDecimal,
        today_pnl: BigDecimal,
        today_pnl_ratio: BigDecimal, 
        list: Vec<HistoryItem>,
    }
    HttpResponse::Ok().json(MyResponse { code: 0, estimated_asset, today_pnl, today_pnl_ratio, list: combined })
}

#[derive(Deserialize)]
pub struct MySerialsQuery {
    pub collection_id: i32,
    pub all: bool,
}

#[get("/my_asset_serials_by_collection")]
async fn my_asset_serials_by_collection(
    auth_user: AuthUser,
    pool: web::Data<DbPool>,
    req: web::Query<MySerialsQuery>,
) -> impl Responder {
    use crate::schema::assets::dsl::*;

    let conn = &mut pool.get().expect("db error");
    let mut query = assets
        .filter(collection_id.eq(req.collection_id))
        .filter(owner_id.eq(auth_user.user_id))
        .into_boxed();
    if !req.all {
        query = query.filter(is_locked.eq(false))
    }
    let results: Vec<String> = query 
        .select(serial_number)
        .order(serial_number)
        .load::<Option<String>>(conn)
        .expect("db error")
        .into_iter()
        .flatten()
        .collect();
    
    #[derive(Serialize)]
    struct MyResponse {
        code: u16,
        list: Vec<String>,
    }
    HttpResponse::Ok().json(MyResponse { code: 0,  list: results })
}

#[derive(Deserialize)]
pub struct BuyOrdersForMySerialsQuery {
    pub collection_id: i32,
}

#[get("/buy_orders_for_my_serials")]
async fn buy_orders_for_my_serials(
    auth_user: AuthUser,
    pool: web::Data<DbPool>,
    req: web::Query<BuyOrdersForMySerialsQuery>,
) -> impl Responder {
    use crate::schema::trade_orders::dsl::*;
    let conn = &mut pool.get().expect("db error");
    let my_serials: Vec<String> = assets::table
        .filter(assets::collection_id.eq(req.collection_id))
        .filter(assets::owner_id.eq(auth_user.user_id))
        .select(assets::serial_number)
        .load::<Option<String>>(conn)
        .expect("db error")
        .into_iter()
        .flatten()
        .collect();

    let orders = trade_orders
        .filter(collection_id.eq(req.collection_id))
        .filter(serial_number.eq_any(&my_serials))
        .filter(side.eq("buy"))
        .filter(status.eq("open"))
        .order(created_at.desc().nulls_last())
        .load::<TradeOrder>(conn)
        .expect("db error");
   
    #[derive(Serialize)]
    struct MyResponse {
        code: u16,
        list: Vec<TradeOrder>,
    }
    HttpResponse::Ok().json(MyResponse { code: 0, list: orders })
}

#[derive(Deserialize)]
pub struct PresaleListRequest {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

#[get("/presale_list")]
async fn presale_list(
    pool: web::Data<DbPool>,
    req: web::Query<PresaleListRequest>,
) -> impl Responder {
    use crate::schema::creations::dsl::*;

    let conn = &mut pool.get().expect("db error");
    let page = req.page.unwrap_or(1).max(1);
    let page_size = req.page_size.unwrap_or(100).clamp(1, 100);
    let offset = (page - 1) * page_size;
    
    let now = Local::now();
    let results = creations
        .filter(trade_option.eq("tradable"))
        .filter(presale_enabled.eq(true))
        .filter(issued_at.is_not_null().and(issued_at.lt(now)))
        .filter(trade_start_at.gt(now))
        .filter(presold_quantity.lt(presale_quantity))
        .offset(offset)
        .limit(page_size)
        .load::<Creation>(conn)
        .expect("db error");

    #[derive(Serialize)]
    struct MyResponse {
        code: u16,
        list: Vec<Creation>,
    }
    HttpResponse::Ok().json(MyResponse { code: 0,  list: results })
}

#[derive(Deserialize)]
pub struct PresaleRequest {
    pub collection_id: i32,
}

enum PresaleOutcome {
    Success(ErrorResponse),
    Failure(ErrorResponse),
}

#[post("/collection_presale")]
async fn collection_presale(
    auth_user: AuthUser,
    pool: web::Data<DbPool>,
    req: web::Json<PresaleRequest>,
) -> impl Responder {
    use crate::schema::creations::dsl::*;
    use crate::schema::accounts::dsl::*;

    let conn = &mut pool.get().expect("db error");
    let req = req.into_inner();
    let result = conn.transaction::<_, diesel::result::Error, _>(|conn| {
        let creation = creations
            .filter(creation_id.eq(req.collection_id))
            .filter(trade_option.eq("tradable"))
            .filter(presale_enabled.eq(true))
            .filter(issued_at.is_not_null().and(issued_at.lt(Local::now())))
            .filter(trade_start_at.gt(Local::now()))
            .filter(presold_quantity.lt(presale_quantity))
            .for_update()  //行级锁
            .first::<Creation>(conn)
            .optional()?;
        let Some(creation) = creation else {
            return Ok(PresaleOutcome::Failure(ErrorResponse { code: 361, message: "预售已结束".into() }));
        };
        let user_balance = accounts
            .filter(user_id.eq(auth_user.user_id))
            .select(balance)
            .first::<Option<BigDecimal>>(conn)?;
        if user_balance < creation.presale_price {
            return Ok(PresaleOutcome::Failure(ErrorResponse { code: 362, message: "余额不足无法购买，请充值。".into() }));
        }
        let asset = assets::table
            .filter(assets::owner_id.eq(creation.creator_id))
            .filter(assets::collection_id.eq(req.collection_id))
            .order(sql::<Float>("RANDOM()"))
            .limit(1)
            .first::<Asset>(conn)?;
        
        diesel::update(creations.filter(creation_id.eq(req.collection_id)))
            .set(presold_quantity.eq(presold_quantity + 1))
            .execute(conn)?;
        diesel::update(assets::table.filter(assets::asset_id.eq(asset.asset_id)))
            .set((
                assets::owner_id.eq(auth_user.user_id),
                assets::source_type.eq("presale"),
                assets::last_price.eq(creation.presale_price.clone()),
                assets::updated_at.eq(Local::now()),
            ))
            .execute(conn)?;

        let updated: Account = diesel::update(accounts.filter(user_id.eq(auth_user.user_id)))
            .set(balance.eq(balance - &creation.presale_price))
            .get_result(conn)?;
        let new_log = NewBalanceLog {
            account_id: auth_user.user_id,
            amount: -creation.presale_price.clone().unwrap_or(0.into()),
            balance_after: updated.balance.unwrap_or(0.into()) + updated.frozen_amount.unwrap_or(0.into()),
            opt_type: "buy".into(),
            memo: Some("预售买入".into()),
            created_at: Some(Local::now()),
        };
        diesel::insert_into(balance_logs::table)
            .values(&new_log)
            .execute(conn)?;

        let updated: Account = diesel::update(accounts.filter(user_id.eq(creation.creator_id)))
            .set(balance.eq(balance + &creation.presale_price))
            .get_result(conn)?;
        let new_log = NewBalanceLog {
            account_id: creation.creator_id,
            amount: creation.presale_price.clone().unwrap_or(0.into()),
            balance_after: updated.balance.unwrap_or(0.into()) + updated.frozen_amount.unwrap_or(0.into()),
            opt_type: "sell".into(),
            memo: Some("预售卖出".into()),
            created_at: Some(Local::now()),
        };
        diesel::insert_into(balance_logs::table)
            .values(&new_log)
            .execute(conn)?;

        Ok(PresaleOutcome::Success(ErrorResponse { code: 0, message: format!("购买成功！编号是 {}", asset.serial_number.as_deref().unwrap())}))
    });
    
    match result {
        Ok(PresaleOutcome::Success(response)) => HttpResponse::Ok().json(response),
        Ok(PresaleOutcome::Failure(response)) => HttpResponse::Ok().json(response),
        Err(_) => HttpResponse::InternalServerError().json(ErrorResponse { code: 503, message: "数据库错误".into() }),
    } 
}

#[derive(Deserialize)]
pub struct TransferRequest {
    pub receiver_id: i32,
    pub collection_id: i32,    
    pub serial_numbers: Vec<String>,
    pub trade_password: String,
}

#[post("/transfer")]
async fn transfer(
    auth_user: AuthUser,
    pool: web::Data<DbPool>,
    req: web::Json<TransferRequest>,
) -> impl Responder {
    use crate::schema::assets::dsl::*;
    use crate::schema::accounts::dsl::*;

    let conn = &mut pool.get().expect("db error");
    let req = req.into_inner();
    let user: Account = accounts
        .filter(user_id.eq(auth_user.user_id))
        .first(conn)
        .expect("db error");
    if !user.trade_password.as_ref().and_then(|hash| verify(&req.trade_password, hash).ok()).unwrap_or(false) {
        return HttpResponse::Forbidden().json(ErrorResponse { code: 111, message: "交易密码错误。".into() });
    }

    let rows = assets
        .filter(owner_id.eq(auth_user.user_id))
        .filter(collection_id.eq(req.collection_id).and(serial_number.eq_any(&req.serial_numbers)))
        .filter(is_locked.eq(false))
        .select((asset_id, serial_number))
        .load::<(i32, Option<String>)>(conn)
        .expect("db error");     
    if rows.is_empty() {
        return HttpResponse::BadRequest().json(ErrorResponse { code: 303, message: "你不拥有编号对应的资产，或者编号已被委托卖单锁定，请先撤单。".into() });
    }
    let (asset_ids, serial_numbers): (Vec<i32>, Vec<Option<String>>) = rows.into_iter().unzip();
    let serials: Vec<String> = serial_numbers.into_iter().flatten().collect();

    if req.receiver_id == auth_user.user_id {
        return HttpResponse::BadRequest().json(ErrorResponse { code: 304, message: "不能转给自己".into() });
    }
    let receiver = accounts
        .filter(user_id.eq(req.receiver_id))
        .select(user_id)
        .first::<i32>(conn)
        .optional()
        .expect("db error");
    if receiver.is_none() {
        return HttpResponse::BadRequest().json(ErrorResponse { code: 404, message: "接收用户不存在".into() });
    }

    diesel::update(assets.filter(asset_id.eq_any(&asset_ids)))
        .set((
            owner_id.eq(req.receiver_id),
            source_type.eq("transfer"),
            last_price.eq(BigDecimal::from(0)),
            updated_at.eq(Local::now()),
        ))
        .execute(conn)
        .expect("db error");

    let new_transfer = NewTransfer {
        sender_id: auth_user.user_id,
        receiver_id: req.receiver_id,
        collection_id: req.collection_id,
        serial_numbers: Some(serials.join(",")),
        quantity: Some(serials.len() as i32),
        estimated_value: Some(0.into()),
        created_at: Some(Local::now()),
    };
    diesel::insert_into(transfers::table)
        .values(&new_transfer)
        .execute(conn)
        .expect("db error");

    let formated_serials = serials.iter().map(|s| format!("#{}", s)).collect::<Vec<_>>().join(", ");
    HttpResponse::Ok().json(ErrorResponse { code: 0, message: format!("成功将资产{}转移给用户{}", formated_serials, req.receiver_id) })
}

#[derive(Deserialize)]
pub struct BusinessAuthRequest {
    pub business_license_url: String,
    pub company_name: String,
    pub social_credit_code: String,
    pub bank_name: String,
    pub bank_account_number: String,
    pub bank_branch_name: Option<String>,
    pub sms_code: String,
}

#[post("/submit_business_auth")]
async fn submit_business_auth(
    auth_user: AuthUser,
    pool: web::Data<DbPool>,
    req: web::Json<BusinessAuthRequest>,
) -> impl Responder {
    use crate::schema::business_auth::dsl::*;
    let conn = &mut pool.get().expect("db error");
    let req = req.into_inner();

    let user: Account = accounts::table
        .filter(accounts::user_id.eq(auth_user.user_id))
        .first(conn)
        .expect("db error");
    if user.sms_code != Some(req.sms_code) {
        return HttpResponse::BadRequest().json(ErrorResponse { code: 603, message: "手机验证码错误".into() });
    }
    if user.sms_code_expire_at.as_ref().map_or(true, |t| t < &Local::now()) {
        return HttpResponse::BadRequest().json(ErrorResponse { code: 604, message: "手机验证码已过期".into() });
    }
    let config: SystemConfig = system_config::table.first(conn).expect("db error");
    if user.balance.as_ref().map_or(true, |v| v < &config.auth_review) {
        return HttpResponse::BadRequest().json ( ErrorResponse { code: 602, message: format!("认证审核费用 {}元，你的余额不足，请充值。", config.auth_review.round(0)) });
    }
    let (balance, frozen): (Option<BigDecimal>, Option<BigDecimal>) = 
        diesel::update(accounts::table.filter(accounts::user_id.eq(auth_user.user_id)))
            .set(accounts::balance.eq(accounts::balance - &config.auth_review))
            .returning((accounts::balance, accounts::frozen_amount))
            .get_result(conn)
            .expect("db error");
    let new_log = NewBalanceLog {
        account_id: auth_user.user_id,
        amount: -config.auth_review.clone(),
        balance_after: balance.unwrap_or(0.into()) + frozen.unwrap_or(0.into()),
        opt_type: "check".into(),
        memo: Some("认证审核费用".into()),
        created_at: Some(Local::now()),
    };
    diesel::insert_into(balance_logs::table)
        .values(&new_log)
        .execute(conn)
        .expect("db error");

    let existing = business_auth
        .filter(account_id.eq(auth_user.user_id))
        .first::<BusinessAuth>(conn)
        .optional()
        .expect("db error");

    match existing {
        Some(auth) => {
            if auth.review_status == "rejected" {
                diesel::update(business_auth.filter(account_id.eq(auth_user.user_id)))
                    .set((
                        business_license_url.eq(req.business_license_url.clone()),
                        company_name.eq(req.company_name.clone()),
                        social_credit_code.eq(req.social_credit_code.clone()),
                        bank_name.eq(req.bank_name.clone()),
                        bank_account_number.eq(req.bank_account_number.clone()),
                        bank_branch_name.eq(req.bank_branch_name.clone()),
                        submitted_at.eq(Local::now()),
                        review_status.eq("pending"),
                    ))
                    .execute(conn)
                    .expect("db error");
                HttpResponse::Ok().json(ErrorResponse { code: 0, message: "提交成功，请等待认证结果".into() }) 
            } else {
                HttpResponse::BadRequest().json(ErrorResponse { code: 601, message: "认证失败才能再次提交".into() }) 
            }
        }
        None => {
            let new_auth = BusinessAuth {
                account_id: auth_user.user_id,
                business_license_url: req.business_license_url.clone(),
                company_name: req.company_name.clone(),
                social_credit_code: req.social_credit_code.clone(),
                bank_name: req.bank_name.clone(),
                bank_account_number: req.bank_account_number.clone(),
                bank_branch_name: req.bank_branch_name.clone(),
                review_status: "pending".to_string(),
                submitted_at: Local::now(),
                verified_at: None,
                reject_reason: None,
            };
            diesel::insert_into(business_auth)
                .values(&new_auth)
                .execute(conn)
                .expect("db error"); 

            diesel::update(accounts::table.filter(accounts::user_id.eq(auth_user.user_id)))
                .set(accounts::account_type.eq("business"))
                .execute(conn)
                .expect("db error");
            HttpResponse::Ok().json(ErrorResponse { code: 0, message: "提交成功，请等待认证结果".into() }) 
        }
    }
}

#[derive(Deserialize)]
pub struct PersonalAuthRequest {
    pub id_card_front_url: String,
    pub id_card_back_url: String,
    pub real_name: String,
    pub id_number: String,
    pub bank_name: String,
    pub bank_account_number: String,
    pub bank_branch_name: Option<String>,
    pub sms_code: String,
}

#[post("/submit_personal_auth")]
async fn submit_personal_auth(
    auth_user: AuthUser,
    pool: web::Data<DbPool>,
    req: web::Json<PersonalAuthRequest>,
) -> impl Responder {
    use crate::schema::personal_auth::dsl::*;
    let conn = &mut pool.get().expect("db error");
    let req = req.into_inner();
    let user: Account = accounts::table
        .filter(accounts::user_id.eq(auth_user.user_id))
        .first(conn)
        .expect("db error");
    if user.sms_code != Some(req.sms_code) {
        return HttpResponse::BadRequest().json(ErrorResponse { code: 603, message: "手机验证码错误".into() });
    }
    if user.sms_code_expire_at.as_ref().map_or(true, |t| t < &Local::now()) {
        return HttpResponse::BadRequest().json(ErrorResponse { code: 604, message: "手机验证码已过期".into() });
    }
    if user.face_cert != Some(true) {
        return HttpResponse::BadRequest().json(ErrorResponse { code: 605, message: "人脸认证没通过".into() });
    }
    let config: SystemConfig = system_config::table.first(conn).expect("db error");
    if user.balance.as_ref().map_or(true, |v| v < &config.auth_review) {
        return HttpResponse::BadRequest().json ( ErrorResponse { code: 602, message: format!("认证审核费用 {}元，你的余额不足，请充值。", config.auth_review.round(0)) });
    }
    let (balance, frozen): (Option<BigDecimal>, Option<BigDecimal>) = 
        diesel::update(accounts::table.filter(accounts::user_id.eq(auth_user.user_id)))
            .set(accounts::balance.eq(accounts::balance - &config.auth_review))
            .returning((accounts::balance, accounts::frozen_amount))
            .get_result(conn)
            .expect("db error");
    let new_log = NewBalanceLog {
        account_id: auth_user.user_id,
        amount: -config.auth_review.clone(),
        balance_after: balance.unwrap_or(0.into()) + frozen.unwrap_or(0.into()),
        opt_type: "check".into(),
        memo: Some("认证审核费用".into()),
        created_at: Some(Local::now()),
    };
    diesel::insert_into(balance_logs::table)
        .values(&new_log)
        .execute(conn)
        .expect("db error");

    let existing = personal_auth
        .filter(account_id.eq(auth_user.user_id))
        .first::<PersonalAuth>(conn)
        .optional()
        .expect("db error");

    match existing {
        Some(auth) => {
            if auth.review_status == "rejected" {
                diesel::update(personal_auth.filter(account_id.eq(auth_user.user_id)))
                    .set((
                        id_card_front_url.eq(req.id_card_front_url.clone()),
                        id_card_back_url.eq(req.id_card_back_url.clone()),
                        real_name.eq(req.real_name.clone()),
                        id_number.eq(req.id_number.clone()),
                        bank_name.eq(req.bank_name.clone()),
                        bank_account_number.eq(req.bank_account_number.clone()),
                        bank_branch_name.eq(req.bank_branch_name.clone()),
                        submitted_at.eq(Local::now()),
                        review_status.eq("pending"),
                    ))
                    .execute(conn)
                    .expect("db error");
                HttpResponse::Ok().json(ErrorResponse { code: 0, message: "提交成功，请等待认证结果".into() }) 
            } else {
                HttpResponse::BadRequest().json(ErrorResponse { code: 601, message: "认证失败才能再次提交".into() }) 
            }
        }
        None => {
            let new_auth = PersonalAuth {
                account_id: auth_user.user_id,
                id_card_front_url: req.id_card_front_url.clone(),
                id_card_back_url: req.id_card_back_url.clone(),
                real_name: req.real_name.clone(),
                id_number: req.id_number.clone(),
                bank_name: req.bank_name.clone(),
                bank_account_number: req.bank_account_number.clone(),
                bank_branch_name: req.bank_branch_name.clone(),
                review_status: "pending".to_string(),
                submitted_at: Local::now(),
                verified_at: None,
                reject_reason: None,
            };
            diesel::insert_into(personal_auth)
                .values(&new_auth)
                .execute(conn)
                .expect("db error"); 

            diesel::update(accounts::table.filter(accounts::user_id.eq(auth_user.user_id)))
                .set(accounts::account_type.eq("personal"))
                .execute(conn)
                .expect("db error");
            HttpResponse::Ok().json(ErrorResponse { code: 0, message: "提交成功，请等待认证结果".into() }) 
        }
    }
}

#[derive(Deserialize)]
pub struct AuthQuery {
    pub account_type: String,
}

#[get("/my_auth")]
async fn my_auth(
    auth_user: AuthUser,
    pool: web::Data<DbPool>,
    req: web::Query<AuthQuery>,
) -> impl Responder {
    let conn = &mut pool.get().expect("db error");
    match req.account_type.as_str() {
        "business" => {
            let auth = business_auth::table
                .filter(business_auth::account_id.eq(auth_user.user_id))
                .first::<BusinessAuth>(conn)
                .optional()
                .expect("db error");
            if auth.is_none() {
                return HttpResponse::Ok().json(ErrorResponse { code: 602, message: "尚未做企业认证".into() });
            }
            #[derive(Serialize)]
            struct MyResponse {
                code: u16,
                auth: BusinessAuth,
            }
            HttpResponse::Ok().json(MyResponse { code: 0, auth: auth.unwrap() })
        } 
        "personal" => {
            let auth = personal_auth::table
                .filter(personal_auth::account_id.eq(auth_user.user_id))
                .first::<PersonalAuth>(conn)
                .optional()
                .expect("db error");
            if auth.is_none() {
                return HttpResponse::Ok().json(ErrorResponse { code: 602, message: "尚未做个人认证".into() });
            }
            #[derive(Serialize)]
            struct MyResponse {
                code: u16,
                auth: PersonalAuth,
            }
            HttpResponse::Ok().json(MyResponse { code: 0, auth: auth.unwrap() })
        }
        _ => {
            HttpResponse::Ok().json(ErrorResponse { code: 602, message: "尚未认证".into() })
        }
    }
}

async fn list_pending_auth(
    pool: web::Data<DbPool>,
    req: web::Query<AuthQuery>,
    _admin: AuthAdmin,
) -> impl Responder {
    let conn = &mut pool.get().expect("Failed to get DB connection");
    match req.account_type.as_str() {
        "business" => {
            let rows = business_auth::table
                .filter(business_auth::review_status.eq("pending"))
                .order(business_auth::submitted_at.desc())
                .load::<BusinessAuth>(conn)
                .expect("db error");
            
            #[derive(Serialize)]
            struct MyResponse {
                code: u16,
                list: Vec<BusinessAuth>,
            }
            HttpResponse::Ok().json(MyResponse { code: 0, list: rows })
        } 
        "personal" => {
            let rows = personal_auth::table
                .filter(personal_auth::review_status.eq("pending"))
                .order(personal_auth::submitted_at.desc())
                .load::<PersonalAuth>(conn)
                .expect("db error");
            
            #[derive(Serialize)]
            struct MyResponse {
                code: u16,
                list: Vec<PersonalAuth>,
            }
            HttpResponse::Ok().json(MyResponse { code: 0, list: rows })
        }
        _ => HttpResponse::Ok().json(ErrorResponse { code: 603, message: "无效的参数".into() }),
    }
}

#[derive(Deserialize)]
pub struct ReviewAuthRequest {
    pub account_id: i32,
    pub account_type: String,
    pub approve: bool,
    pub reject_reason: Option<String>,
}

async fn review_auth(
    _admin: AuthAdmin,
    pool: web::Data<DbPool>,
    req: web::Json<ReviewAuthRequest>,
) -> impl Responder {  
    let conn = &mut pool.get().expect("Failed to get DB connection");
    let config: SystemConfig = system_config::table.first(conn).expect("db error");
    if !req.approve {
        if req.reject_reason.is_none() {
            return HttpResponse::BadRequest().json(ErrorResponse { code: 205, message: "拒绝时必须填写失败原因".into() });
        }
        let (balance, frozen): (Option<BigDecimal>, Option<BigDecimal>) = 
            diesel::update(accounts::table.filter(accounts::user_id.eq(req.account_id)))
                .set(accounts::balance.eq(accounts::balance + &config.auth_review))
                .returning((accounts::balance, accounts::frozen_amount))
                .get_result(conn)
                .expect("db error");
        let new_log = NewBalanceLog {
            account_id: req.account_id,
            amount: config.auth_review.clone(),
            balance_after: balance.unwrap_or(0.into()) + frozen.unwrap_or(0.into()),
            opt_type: "refund".into(),
            memo: Some("认证审核费用退款".into()),
            created_at: Some(Local::now()),
        };
        diesel::insert_into(balance_logs::table)
            .values(&new_log)
            .execute(conn)
            .expect("db error");
    }
    match req.account_type.as_str() {
        "business" => {
            use crate::schema::business_auth::dsl::*;
            use crate::schema::accounts::dsl::*;
            let _ = business_auth
                .filter(account_id.eq(req.account_id))
                .filter(review_status.eq("pending"))
                .first::<BusinessAuth>(conn)
                .expect("db error");
            
            if req.approve {
                diesel::update(business_auth.filter(account_id.eq(req.account_id)))
                    .set((
                        review_status.eq("approved"),
                        verified_at.eq(Local::now())
                    ))
                    .execute(conn)
                    .expect("db error");
                diesel::update(accounts.filter(user_id.eq(req.account_id)))
                    .set((
                        account_type.eq("business"),
                        is_verified.eq(true),
                    ))
                    .execute(conn)
                    .expect("db error");
            } else {
                diesel::update(business_auth.filter(account_id.eq(req.account_id)))
                    .set((
                        review_status.eq("rejected"),
                        reject_reason.eq(req.reject_reason.clone())
                    ))
                    .execute(conn)
                    .expect("db error");    
            }
            HttpResponse::Ok().json(ErrorResponse { code: 0, message: "操作成功".into() })
        } 
        "personal" => {
            use crate::schema::personal_auth::dsl::*;
            use crate::schema::accounts::dsl::*;
            let _ = personal_auth
                .filter(account_id.eq(req.account_id))
                .filter(review_status.eq("pending"))
                .first::<PersonalAuth>(conn)
                .expect("db error");
            
            if req.approve {
                diesel::update(personal_auth.filter(account_id.eq(req.account_id)))
                    .set((
                        review_status.eq("approved"),
                        verified_at.eq(Local::now())
                    ))
                    .execute(conn)
                    .expect("db error");
                diesel::update(accounts.filter(user_id.eq(req.account_id)))
                    .set((
                        account_type.eq("personal"),
                        is_verified.eq(true),
                    ))
                    .execute(conn)
                    .expect("db error");
            } else {
                diesel::update(personal_auth.filter(account_id.eq(req.account_id)))
                    .set((
                        review_status.eq("rejected"),
                        reject_reason.eq(req.reject_reason.clone())
                    ))
                    .execute(conn)
                    .expect("db error");
            }
            HttpResponse::Ok().json(ErrorResponse { code: 0, message: "操作成功".into() })
        }
        _ => HttpResponse::Ok().json(ErrorResponse { code: 603, message: "无效的参数".into() }),
    }
}

#[post("/upload_auth")]
async fn upload_auth(
    mut payload: Multipart,
    _auth_user: AuthUser,
) -> actix_web::Result<HttpResponse> {
    let mut url = None;
    while let Some(field) = payload.next().await {
        let mut field = field?;
        let filename = format!("{}.png", uuid::Uuid::new_v4());
        let filepath = format!("./auths/{}", filename);
    
        let mut f = fs::File::create(&filepath).await?;
        while let Some(chunk) = field.next().await {
            let data = chunk?;
            tokio::io::AsyncWriteExt::write_all(&mut f, &data).await?;
        }
        url = Some(format!("/auths/{}", filename));
        break; 
    }
    let Some(url) = url else {
        return Ok(HttpResponse::BadRequest().body("No file uploaded"));
    };
    Ok(HttpResponse::Ok().json(serde_json::json!({ "code": 0, "url": url })))
}

#[get("/vip_plans")]
async fn get_vip_plans(pool: web::Data<DbPool>) -> impl Responder {
    use crate::schema::vip_plans::dsl::*;
    let conn = &mut pool.get().expect("db error");
    let rows = vip_plans
        .order(plan_id)
        .load::<VipPlan>(conn)
        .expect("db error");
    #[derive(Serialize)]
    struct MyResponse {
        code: u16,
        list: Vec<VipPlan>,
    }
    HttpResponse::Ok().json(MyResponse { code: 0, list: rows })
}

#[derive(Deserialize)]
pub struct SubscribeVIPRequest {
    pub plan_id: i32,
}

#[post("/subscribe_vip")]
async fn subscribe_vip(
    auth_user: AuthUser,
    pool: web::Data<DbPool>,
    req: web::Json<SubscribeVIPRequest>,
) -> impl Responder {
    use crate::schema::accounts::dsl::*;
    use crate::schema::vip_plans::dsl::*;

    let conn = &mut pool.get().expect("db error");
    let user: Account = accounts
        .filter(user_id.eq(auth_user.user_id))
        .first(conn)
        .expect("db error");
    if user.is_verified != Some(true) {
        return HttpResponse::Forbidden().json(ErrorResponse { code: 110, message: "用户尚未认证，请先做认证。".into() });
    }
    let plan: VipPlan = vip_plans
        .filter(plan_id.eq(req.plan_id))
        .first(conn)
        .expect("db error");
    if user.balance.as_ref().map(|v| v < &plan.promo_price).unwrap_or(true) {
        return HttpResponse::Forbidden().json(ErrorResponse { code: 112, message: "余额不足，请先充值。".into() });
    }
    
    let interval = format!("interval '{} months'", plan.duration_months);
    let is_expired = user.vip_expire_at.map_or(true, |t| t < Local::now());
    let expr_sql = if is_expired {
        format!("NOW() + {}", interval)
    } else {
        format!("vip_expire_at + {}", interval)
    };
    let new_expire_at = sql::<Nullable<Timestamptz>>(&expr_sql);
    let updated: Account = diesel::update(accounts.filter(user_id.eq(user.user_id)))
        .set((
            vip_expire_at.eq(new_expire_at),
            is_vip.eq(true),
            balance.eq(balance - &plan.promo_price)
        ))
        .get_result(conn)
        .expect("db error");

    let new_log = NewBalanceLog {
        account_id: user.user_id,
        amount: -plan.promo_price.clone(),
        balance_after: updated.balance.unwrap_or(0.into()) + updated.frozen_amount.unwrap_or(0.into()),
        opt_type: "fee".into(),
        memo: Some("订阅VIP费用".into()),
        created_at: Some(Local::now()),
    };
    diesel::insert_into(balance_logs::table)
        .values(&new_log)
        .execute(conn)
        .expect("db error");

    HttpResponse::Ok().json(ErrorResponse { code: 0, message: format!("开通会员成功，会员有效期到 {}", updated.vip_expire_at.unwrap().format("%Y.%m.%d")) })
}

#[derive(Deserialize)]
pub struct MyBalanceLogQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub opt_type: Option<String>,
}

#[get("/my_balance_log")]
async fn my_balance_log(
    auth_user: AuthUser,
    pool: web::Data<DbPool>,
    req: web::Query<MyBalanceLogQuery>,
) -> impl Responder {
    use crate::schema::balance_logs::dsl::*;

    let conn = &mut pool.get().expect("db error");
    let page = req.page.unwrap_or(1).max(1);
    let page_size = req.page_size.unwrap_or(100).clamp(1, 100);
    let offset = (page - 1) * page_size;
    
    let mut query = balance_logs
        .filter(account_id.eq(auth_user.user_id))
        .into_boxed();
    if let Some(otype) = req.opt_type.as_ref() {
        query = query.filter(opt_type.eq(otype))
    }
    let results = query
        .order(log_id.desc())
        .offset(offset)
        .limit(page_size)
        .load::<BalanceLog>(conn)
        .expect("db error");    
    
    let mut query2 = balance_logs
        .filter(account_id.eq(auth_user.user_id))
        .into_boxed();
    if let Some(otype) = req.opt_type.as_ref() {
        query2 = query2.filter(opt_type.eq(otype))
    }
    let total_count: i64 = query2
        .count()
        .get_result(conn)
        .expect("db error");

    #[derive(Serialize)]
    struct MyResponse {
        code: u16,
        total_count: i64,
        list: Vec<BalanceLog>,
    }
    HttpResponse::Ok().json(MyResponse { code: 0, total_count, list: results })
}

#[derive(Deserialize)]
pub struct CheckSMSRequest {
    pub sms_code: String,
}

#[post("/check_sms_code")]
async fn check_sms_code(
    auth_user: AuthUser,
    pool: web::Data<DbPool>,
    req: web::Json<CheckSMSRequest>,
) -> impl Responder {
    use crate::schema::accounts::dsl::*;
    let conn = &mut pool.get().expect("db error");
    let req = req.into_inner();

    let user: Account = accounts
        .filter(user_id.eq(auth_user.user_id))
        .first(conn)
        .expect("db error");
    if user.sms_code != Some(req.sms_code) {
        return HttpResponse::BadRequest().json(ErrorResponse { code: 603, message: "手机验证码错误".into() });
    }
    if user.sms_code_expire_at.as_ref().map_or(true, |t| t < &Local::now()) {
        return HttpResponse::BadRequest().json(ErrorResponse { code: 604, message: "手机验证码已过期".into() });
    }
    HttpResponse::Ok().json(ErrorResponse { code: 0, message: "手机验证码正确".into() })
}

#[derive(Deserialize)]
pub struct CheckSMSForRegisterRequest {
    pub phone: String,
    pub sms_code: String,
}

#[get("/check_sms_code_for_register")]
async fn check_sms_code_for_register(
    pool: web::Data<DbPool>,
    req: web::Query<CheckSMSForRegisterRequest>,
) -> impl Responder {
    use crate::schema::smscodes::dsl::*;
    let conn = &mut pool.get().expect("db error");
    let req = req.into_inner();

    let sms = smscodes
        .filter(phone.eq(&req.phone))
        .first::<SmsCode>(conn)
        .optional()
        .expect("db error");
    let Some(sms) = sms else {
        return HttpResponse::BadRequest().json(ErrorResponse { code: 602, message: "手机号不正确".into() });
    };
    if sms.sms_code != Some(req.sms_code) {
        return HttpResponse::BadRequest().json(ErrorResponse { code: 603, message: "手机验证码错误".into() });
    }
    if sms.expire_at.as_ref().map_or(true, |t| t < &Local::now()) {
        return HttpResponse::BadRequest().json(ErrorResponse { code: 604, message: "手机验证码已过期".into() });
    }
    HttpResponse::Ok().json(ErrorResponse { code: 0, message: "手机验证码正确".into() })
}

#[get("/boost_plans")]
async fn get_boost_plans(pool: web::Data<DbPool>) -> impl Responder {
    use crate::schema::boost_plans::dsl::*;
    let conn = &mut pool.get().expect("db error");
    let rows = boost_plans
        .order(plan_id)
        .load::<BoostPlan>(conn)
        .expect("db error");
    #[derive(Serialize)]
    struct MyResponse {
        code: u16,
        list: Vec<BoostPlan>,
    }
    HttpResponse::Ok().json(MyResponse { code: 0, list: rows })
}

#[derive(Deserialize)]
pub struct BuyBoostRequest {
    pub collection_id: i32,
    pub plan_id: i32,
}

#[post("/buy_boost")]
async fn buy_boost(
    auth_user: AuthUser,
    pool: web::Data<DbPool>,
    req: web::Json<BuyBoostRequest>,
) -> impl Responder {
    use crate::schema::accounts::dsl::*;
    use crate::schema::boost_plans::dsl::*;
    use crate::schema::collections::dsl::*;

    let conn = &mut pool.get().expect("db error");
    let user: Account = accounts
        .filter(user_id.eq(auth_user.user_id))
        .first(conn)
        .expect("db error");
    let plan: BoostPlan = boost_plans
        .filter(plan_id.eq(req.plan_id))
        .first(conn)
        .expect("db error");
    if user.balance.as_ref().map(|v| v < &plan.price).unwrap_or(true) {
        return HttpResponse::Forbidden().json(ErrorResponse { code: 112, message: "余额不足，请先充值。".into() });
    }

    let expr_expire = format!("NOW() + interval '{} hours'", plan.duration_hours);
    diesel::insert_into(boosts::table)
        .values((
            boosts::collection_id.eq(req.collection_id),
            boosts::score.eq(plan.score),
            boosts::expire_at.eq(sql::<Timestamptz>(&expr_expire)),
        ))
        .execute(conn)
        .expect("db error");

    let expr_boost = format!("LEAST(boost + {}, 2000)", plan.score);
    diesel::update(collections.filter(collection_id.eq(req.collection_id)))
        .set(boost.eq(sql::<Nullable<Integer>>(&expr_boost)))
        .execute(conn)
        .expect("db error");
    
    let updated: Account = diesel::update(accounts.filter(user_id.eq(user.user_id)))
        .set(balance.eq(balance - &plan.price))
        .get_result(conn)
        .expect("db error");
    let new_log = NewBalanceLog {
        account_id: user.user_id,
        amount: -plan.price.clone(),
        balance_after: updated.balance.unwrap_or(0.into()) + updated.frozen_amount.unwrap_or(0.into()),
        opt_type: "fee".into(),
        memo: Some("购买推广分".into()),
        created_at: Some(Local::now()),
    };
    diesel::insert_into(balance_logs::table)
        .values(&new_log)
        .execute(conn)
        .expect("db error");

    HttpResponse::Ok().json(ErrorResponse { code: 0, message: "购买推广分成功".into() })
}

#[derive(Debug, Deserialize)]
struct MetadataItem {
    jump_type: String,
    jump_url: Option<String>,
    collection_id: Option<i32>,
}

async fn set_banner(
    mut payload: Multipart,
    _admin: AuthAdmin,
    pool: web::Data<DbPool>,
) -> Result<HttpResponse, Box<dyn std::error::Error>> {
    let mut metadata_list: Vec<MetadataItem> = Vec::new();
    let mut banner_urls: Vec<String> = Vec::new();
    while let Some(item) = payload.next().await {
        let mut field = item?;
        let content_disposition = field.content_disposition();
        let field_name = content_disposition.parameters.iter()
            .find_map(|param| { if let DispositionParam::Name(name) = param { Some(name.clone())} else { None } })
            .unwrap_or_default();
        if field_name == "metadata" {
            let mut data_bytes = Vec::new();
            while let Some(chunk) = field.next().await {
                data_bytes.extend_from_slice(&chunk?);
            }
            metadata_list = serde_json::from_slice::<Vec<MetadataItem>>(&data_bytes)?;
        } else if field_name == "images" {
            let filepath = format!("./uploads/{}.png", uuid::Uuid::new_v4());
            let mut f = fs::File::create(&filepath).await?;
            while let Some(chunk) = field.next().await {
                let data = chunk?;
                tokio::io::AsyncWriteExt::write_all(&mut f, &data).await?;
            }
            banner_urls.push(filepath.strip_prefix(".").unwrap().to_string());
        }
    }
    if metadata_list.len() != banner_urls.len() {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse { code: 0, message: "元数据JSON数组长度和图片数组长度不匹配".into() }));
    }

    let conn = &mut pool.get().expect("db error");
    diesel::delete(banners::table)
        .execute(conn)?;
    let new_banners: Vec<NewBanner> = metadata_list
        .into_iter()
        .zip(banner_urls.into_iter())
        .map(|(meta, url)| NewBanner {
            banner_url: Some(url),
            jump_type: Some(meta.jump_type),
            jump_url: meta.jump_url,
            collection_id: meta.collection_id,
        })
        .collect();
    diesel::insert_into(banners::table)
        .values(&new_banners)
        .execute(conn)?;
    Ok(HttpResponse::BadRequest().json(ErrorResponse {code: 0, message: "操作成功".into()}))
}

#[get("/banners")]
async fn get_banners(pool: web::Data<DbPool>) -> impl Responder {
    use crate::schema::banners::dsl::*;
    let conn = &mut pool.get().expect("db error");
    let rows = banners
        .order(banner_id)
        .load::<Banner>(conn)
        .expect("db error");
    #[derive(Serialize)]
    struct MyResponse {
        code: u16,
        list: Vec<Banner>,
    }
    HttpResponse::Ok().json(MyResponse { code: 0, list: rows })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let manager = ConnectionManager::<PgConnection>::new(db_url);
    let pool = r2d2::Pool::builder().build(manager).expect("Failed to create pool");

    println!("Server running at http://127.0.0.1:8080");

    HttpServer::new(move || {
        App::new()
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allowed_methods(vec!["GET", "POST"])
                    .allowed_headers(vec!["Content-Type", "Authorization"])
                    .supports_credentials()
                    .max_age(3600)
            )
            .app_data(web::Data::new(pool.clone()))
            .app_data(PayloadConfig::new(10 * 1024 * 1024)) 
            .service(
                web::scope("/admin")
                    .route("/set_config", web::post().to(set_config))
                    .route("/list_pending_creations", web::get().to(list_pending_creations))
                    .route("/review_creation", web::post().to(review_creation))
                    .route("/list_pending_auth", web::get().to(list_pending_auth))
                    .route("/review_auth", web::post().to(review_auth))
                    .route("/set_banner", web::post().to(set_banner))
            )       
            .service(register_account)
            .service(login_account)
            .service(get_user_info)
            .service(set_trade_password)
            .service(change_nickname)
            .service(upload_avatar)
            .service(upload_image)
            .service(Files::new("/avatars", "./avatars").show_files_listing())
            .service(Files::new("/uploads", "./uploads").show_files_listing())
            .service(get_config)
            .service(new_creation)
            .service(update_creation)
            .service(my_creations)
            .service(list_collections)
            .service(my_collections)
            .service(collection_info)
            .service(place_order)
            .service(cancel_order)
            .service(match_order)
            .service(filled_orders_by_collection)
            .service(open_orders_by_collection)
            .service(collection_holders)
            .service(my_open_orders_by_collection)
            .service(my_asset_serials_by_collection)
            .service(presale_list)
            .service(collection_presale)
            .service(transfer)
            .service(kline_data_by_collection)
            .service(buy_orders_for_my_serials)
            .service(my_trade_history)
            .service(submit_personal_auth)
            .service(submit_business_auth)
            .service(my_auth)
            .service(upload_auth)
            .service(get_vip_plans)
            .service(subscribe_vip)
            .service(my_balance_log)
            .service(check_sms_code)
            .service(get_boost_plans)
            .service(buy_boost)
            .service(recommendations)
            .service(select_collection_to_boost)
            .service(get_banners)
            .service(check_sms_code_for_register)
            .service(change_trade_password)
            .service(change_login_password)
            .service(change_phone)
            .service(close_account)
            .service(my_trade_history_by_collection)
            .service(forgot_password)
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}