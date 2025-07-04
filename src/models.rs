use serde::{Deserialize, Serialize};
use diesel::{Queryable, Insertable, Associations};
use chrono::{DateTime, Local};
use bigdecimal::BigDecimal;
use crate::schema::{
    accounts, creations, assets, trade_orders, kline_data, 
    personal_auth, business_auth, balance_logs, boosts, banners, transfers,
};

#[derive(Queryable, Serialize)]
pub struct Account {
    pub user_id: i32,
    pub phone: String,
    pub login_password: String,
    pub trade_password: Option<String>,
    pub avatar: Option<String>,
    pub nickname: Option<String>,
    pub is_verified: Option<bool>,
    pub is_admin: Option<bool>,
    pub is_vip: Option<bool>,
    pub vip_expire_at: Option<DateTime<Local>>,
    pub account_type: Option<String>,
    pub account_status: Option<String>,
    pub total_asset_today: Option<BigDecimal>,
    pub total_asset_yesterday: Option<BigDecimal>,
    pub balance: Option<BigDecimal>,
    pub frozen_amount: Option<BigDecimal>,
    pub recharge_method: Option<String>,
    pub withdraw_account: Option<String>,
    pub sms_code: Option<String>,
    pub sms_code_expire_at: Option<DateTime<Local>>,
    pub login_retry_count: Option<i32>,
    pub unlock_time_if_locked: Option<DateTime<Local>>,
    pub created_at: Option<DateTime<Local>>,
    pub face_cert: Option<bool>,
}

#[derive(Insertable, Serialize, Deserialize)]
#[diesel(table_name = accounts)]
pub struct NewAccount {
    pub phone: String,
    pub login_password: String,
    pub trade_password: Option<String>,
    pub avatar: Option<String>,
    pub nickname: Option<String>,
    pub is_verified: Option<bool>,
    pub is_admin: Option<bool>,
    pub is_vip: Option<bool>,
    pub vip_expire_at: Option<DateTime<Local>>,
    pub account_type: Option<String>,
    pub account_status: Option<String>,
    pub total_asset_today: Option<BigDecimal>,
    pub total_asset_yesterday: Option<BigDecimal>,
    pub balance: Option<BigDecimal>,
    pub frozen_amount: Option<BigDecimal>,
    pub recharge_method: Option<String>,
    pub withdraw_account: Option<String>,
    pub sms_code: Option<String>,
    pub sms_code_expire_at: Option<DateTime<Local>>,
    pub login_retry_count: Option<i32>,
    pub unlock_time_if_locked: Option<DateTime<Local>>,
    pub created_at: Option<DateTime<Local>>,
    pub face_cert: Option<bool>,
}

#[derive(Queryable, Serialize, Associations)]
#[diesel(belongs_to(Account, foreign_key = creator_id))]
pub struct Creation {
    pub creation_id: i32,
    pub creator_id: i32,
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
    pub review_status: Option<String>,
    pub submitted_at: Option<DateTime<Local>>,
    pub rejected_at: Option<DateTime<Local>>,
    pub reject_reason: Option<String>,
    pub contract_address: Option<String>,
    pub issued_at: Option<DateTime<Local>>,
    pub presale_quantity: Option<i32>,
    pub presold_quantity: Option<i32>,
}

#[derive(Insertable, Serialize, Deserialize)]
#[diesel(table_name = creations)]
pub struct NewCreation {
    pub creator_id: i32,
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
    pub review_status: Option<String>,
    pub submitted_at: Option<DateTime<Local>>,
    pub rejected_at: Option<DateTime<Local>>,
    pub reject_reason: Option<String>,
    pub contract_address: Option<String>,
    pub issued_at: Option<DateTime<Local>>,
    pub presale_quantity: Option<i32>,
    pub presold_quantity: Option<i32>,
}

#[derive(Queryable, Serialize, Deserialize, Debug)]
#[diesel(table_name = collections)]
pub struct Collection {
    pub collection_id: i32,
    pub last_trade_price: Option<BigDecimal>,
    pub high_24h: Option<BigDecimal>,
    pub low_24h: Option<BigDecimal>,
    pub volume_24h: Option<BigDecimal>,
    pub count_24h: Option<i32>,
    pub all_time_low: Option<BigDecimal>,
    pub all_time_high: Option<BigDecimal>,
    pub all_time_volume: Option<BigDecimal>,
    pub all_time_count: Option<i32>,
    pub market_cap: Option<BigDecimal>,
    pub updated_at: Option<DateTime<Local>>,
    pub is_tradable: Option<bool>,
    pub boost: Option<i32>,
    pub recommend_score: Option<BigDecimal>,
    pub yesterday_price: Option<BigDecimal>
}

#[derive(Queryable, Serialize, Deserialize, Debug)]
pub struct Asset {
    pub asset_id: i32,
    pub asset_name: Option<String>,
    pub collection_id: i32,
    pub serial_number: Option<String>,
    pub nft_address: Option<String>,
    pub is_locked: Option<bool>,
    pub last_price: Option<BigDecimal>,
    pub owner_id: i32,
    pub source_type: Option<String>,
    pub updated_at: Option<DateTime<Local>>,
}

#[derive(Insertable, Deserialize)]
#[diesel(table_name = assets)]
pub struct NewAsset {
    pub asset_name: Option<String>,
    pub collection_id: i32,
    pub serial_number: Option<String>,
    pub nft_address: Option<String>,
    pub is_locked: Option<bool>,
    pub last_price: Option<BigDecimal>,
    pub owner_id: i32,
    pub source_type: Option<String>,
    pub updated_at: Option<DateTime<Local>>,
}

#[derive(Queryable, Serialize, Deserialize, Debug)]
pub struct TradeOrder {
    pub order_id: i32,
    pub maker_id: i32,
    pub taker_id: Option<i32>,
    pub side: String, 
    pub collection_id: i32,
    pub serial_number: Option<String>,
    pub price: BigDecimal,
    pub status: Option<String>,
    pub created_at: Option<DateTime<Local>>,
    pub filled_at: Option<DateTime<Local>>,
    pub fee: BigDecimal,
}

#[derive(Insertable, Deserialize, Debug)]
#[diesel(table_name = trade_orders)]
pub struct NewTradeOrder {
    pub maker_id: i32,
    pub taker_id: Option<i32>,
    pub side: String,
    pub collection_id: i32,
    pub serial_number: Option<String>,
    pub price: BigDecimal,
    pub status: Option<String>,
    pub created_at: Option<DateTime<Local>>,
    pub filled_at: Option<DateTime<Local>>,
    pub fee: BigDecimal,
}

#[derive(Queryable, Serialize, Deserialize, Debug)]
#[diesel(primary_key(collection_id, interval, timestamp))]
pub struct KlineData {
    pub collection_id: i32,
    pub interval: i32,
    pub timestamp: DateTime<Local>,
    pub close_price: BigDecimal,
    pub high_price: BigDecimal,
    pub low_price: BigDecimal,
    pub trade_volume: BigDecimal,
    pub trade_count: i32,
}

#[derive(Insertable, Deserialize)]
#[diesel(table_name = kline_data)]
pub struct NewKlineData {
    pub collection_id: i32,
    pub interval: i32,
    pub timestamp: DateTime<Local>,
    pub close_price: BigDecimal,
    pub high_price: BigDecimal,
    pub low_price: BigDecimal,
    pub trade_volume: BigDecimal,
    pub trade_count: i32,
}

#[derive(Queryable, Serialize, Deserialize, Debug)]
pub struct Transfer {
    pub transfer_id: i32,
    pub sender_id: i32,
    pub receiver_id: i32,
    pub collection_id: i32,
    pub created_at: Option<DateTime<Local>>,
    pub serial_numbers: Option<String>, 
    pub estimated_value: Option<BigDecimal>,
    pub quantity: Option<i32>,
}

#[derive(Insertable, Deserialize)]
#[diesel(table_name = transfers)]
pub struct NewTransfer {
    pub sender_id: i32,
    pub receiver_id: i32,
    pub collection_id: i32,
    pub created_at: Option<DateTime<Local>>,
    pub serial_numbers: Option<String>, 
    pub estimated_value: Option<BigDecimal>,
    pub quantity: Option<i32>,
}

#[derive(Queryable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = business_auth)]
pub struct BusinessAuth {
    pub account_id: i32,
    pub business_license_url: String,
    pub company_name: String,
    pub social_credit_code: String,
    pub bank_name: String,
    pub bank_account_number: String,
    pub bank_branch_name: Option<String>,
    pub review_status: String,
    pub submitted_at: DateTime<Local>,
    pub verified_at: Option<DateTime<Local>>,
    pub reject_reason: Option<String>,
}

#[derive(Queryable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = personal_auth)]
pub struct PersonalAuth {
    pub account_id: i32,
    pub id_card_front_url: String,
    pub id_card_back_url: String,
    pub real_name: String,
    pub id_number: String,
    pub bank_name: String,
    pub bank_account_number: String,
    pub bank_branch_name: Option<String>,
    pub review_status: String,
    pub submitted_at: DateTime<Local>,
    pub verified_at: Option<DateTime<Local>>,
    pub reject_reason: Option<String>,
}

#[derive(Queryable, Serialize, Deserialize)]
#[diesel(table_name = vip_plans)]
pub struct VipPlan {
    pub plan_id: i32,
    pub name: String,
    pub duration_months: i32,
    pub base_price: BigDecimal,
    pub promo_price: BigDecimal,
    pub description: Option<String>,
}

#[derive(Queryable, Serialize, Deserialize)]
pub struct BoostPlan {
    pub plan_id: i32,
    pub score: i32,
    pub duration_hours: i32,
    pub price: BigDecimal,
}

#[derive(Queryable, Serialize, Deserialize)]
pub struct Boost {
    pub boost_id: i32,
    pub collection_id: i32,
    pub score: i32,
    pub expire_at: DateTime<Local>,
}

#[derive(Insertable, Deserialize)]
#[diesel(table_name = boosts)]
pub struct NewBoost {
    pub collection_id: i32,
    pub score: i32,
    pub expire_at: DateTime<Local>,
}

#[derive(Queryable, Serialize, Deserialize)]
pub struct Banner {
    pub banner_id: i32,
    pub banner_url: Option<String>,
    pub jump_type: Option<String>,
    pub jump_url: Option<String>,
    pub collection_id: Option<i32>,
}

#[derive(Insertable, Deserialize)]
#[diesel(table_name = banners)]
pub struct NewBanner {
    pub banner_url: Option<String>,
    pub jump_type: Option<String>,
    pub jump_url: Option<String>,
    pub collection_id: Option<i32>,
}

#[derive(Queryable, Serialize, Deserialize)]
pub struct SmsCode {
    pub phone: String,
    pub sms_code: Option<String>,
    pub expire_at: Option<DateTime<Local>>, 
}

#[derive(Queryable, Serialize, Deserialize)]
#[diesel(table_name = system_config)]
pub struct SystemConfig {
    pub id: bool,
    pub fee_mode: String,
    pub trade_fee: BigDecimal,
    pub withdraw_fee: BigDecimal,
    pub vip_trade_fee: BigDecimal,
    pub vip_withdraw_fee: BigDecimal,
    pub issue_review: BigDecimal,
    pub auth_review: BigDecimal,
}

#[derive(Queryable, Serialize, Deserialize)]
pub struct BalanceLog {
    pub log_id: i32,
    pub account_id: i32,
    pub amount: BigDecimal,
    pub balance_after: BigDecimal,
    pub opt_type: String,
    pub memo: Option<String>,
    pub created_at: Option<DateTime<Local>>,
}

#[derive(Insertable, Deserialize)]
#[diesel(table_name = balance_logs)]
pub struct NewBalanceLog {
    pub account_id: i32,
    pub amount: BigDecimal,
    pub balance_after: BigDecimal,
    pub opt_type: String,
    pub memo: Option<String>,
    pub created_at: Option<DateTime<Local>>,
}
