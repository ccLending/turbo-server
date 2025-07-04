// @generated automatically by Diesel CLI.

diesel::table! {
    accounts (user_id) {
        user_id -> Int4,
        #[max_length = 20]
        phone -> Varchar,
        login_password -> Text,
        trade_password -> Nullable<Text>,
        avatar -> Nullable<Text>,
        #[max_length = 30]
        nickname -> Nullable<Varchar>,
        is_verified -> Nullable<Bool>,
        is_admin -> Nullable<Bool>,
        is_vip -> Nullable<Bool>,
        vip_expire_at -> Nullable<Timestamptz>,
        account_type -> Nullable<Text>,
        account_status -> Nullable<Text>,
        total_asset_today -> Nullable<Numeric>,
        total_asset_yesterday -> Nullable<Numeric>,
        balance -> Nullable<Numeric>,
        frozen_amount -> Nullable<Numeric>,
        recharge_method -> Nullable<Text>,
        withdraw_account -> Nullable<Text>,
        #[max_length = 10]
        sms_code -> Nullable<Varchar>,
        sms_code_expire_at -> Nullable<Timestamptz>,
        login_retry_count -> Nullable<Int4>,
        unlock_time_if_locked -> Nullable<Timestamptz>,
        created_at -> Nullable<Timestamptz>,
        face_cert -> Nullable<Bool>,
    }
}

diesel::table! {
    assets (asset_id) {
        asset_id -> Int4,
        asset_name -> Nullable<Text>,
        collection_id -> Int4,
        #[max_length = 6]
        serial_number -> Nullable<Varchar>,
        nft_address -> Nullable<Text>,
        is_locked -> Nullable<Bool>,
        last_price -> Nullable<Numeric>,
        owner_id -> Int4,
        source_type -> Nullable<Text>,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    balance_logs (log_id) {
        log_id -> Int4,
        account_id -> Int4,
        amount -> Numeric,
        balance_after -> Numeric,
        opt_type -> Text,
        memo -> Nullable<Text>,
        created_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    banners (banner_id) {
        banner_id -> Int4,
        banner_url -> Nullable<Text>,
        jump_type -> Nullable<Text>,
        jump_url -> Nullable<Text>,
        collection_id -> Nullable<Int4>,
    }
}

diesel::table! {
    boost_plans (plan_id) {
        plan_id -> Int4,
        score -> Int4,
        duration_hours -> Int4,
        price -> Numeric,
    }
}

diesel::table! {
    boosts (boost_id) {
        boost_id -> Int4,
        collection_id -> Int4,
        score -> Int4,
        expire_at -> Timestamptz,
    }
}

diesel::table! {
    business_auth (account_id) {
        account_id -> Int4,
        business_license_url -> Text,
        company_name -> Text,
        social_credit_code -> Text,
        bank_name -> Text,
        bank_account_number -> Text,
        bank_branch_name -> Nullable<Text>,
        review_status -> Text,
        submitted_at -> Timestamptz,
        verified_at -> Nullable<Timestamptz>,
        reject_reason -> Nullable<Text>,
    }
}

diesel::table! {
    collections (collection_id) {
        collection_id -> Int4,
        last_trade_price -> Nullable<Numeric>,
        high_24h -> Nullable<Numeric>,
        low_24h -> Nullable<Numeric>,
        volume_24h -> Nullable<Numeric>,
        count_24h -> Nullable<Int4>,
        all_time_low -> Nullable<Numeric>,
        all_time_high -> Nullable<Numeric>,
        all_time_volume -> Nullable<Numeric>,
        all_time_count -> Nullable<Int4>,
        market_cap -> Nullable<Numeric>,
        updated_at -> Nullable<Timestamptz>,
        is_tradable -> Nullable<Bool>,
        boost -> Nullable<Int4>,
        recommend_score -> Nullable<Numeric>,
        yesterday_price -> Nullable<Numeric>,
    }
}

diesel::table! {
    creations (creation_id) {
        creation_id -> Int4,
        creator_id -> Int4,
        title -> Text,
        cover_image -> Nullable<Text>,
        description -> Nullable<Text>,
        total_supply -> Int4,
        trade_option -> Nullable<Text>,
        trade_start_at -> Nullable<Timestamptz>,
        issue_price -> Nullable<Numeric>,
        presale_enabled -> Nullable<Bool>,
        presale_ratio -> Nullable<Numeric>,
        presale_price -> Nullable<Numeric>,
        review_status -> Nullable<Text>,
        submitted_at -> Nullable<Timestamptz>,
        rejected_at -> Nullable<Timestamptz>,
        reject_reason -> Nullable<Text>,
        contract_address -> Nullable<Text>,
        issued_at -> Nullable<Timestamptz>,
        presale_quantity -> Nullable<Int4>,
        presold_quantity -> Nullable<Int4>,
    }
}

diesel::table! {
    kline_data (collection_id, interval, timestamp) {
        collection_id -> Int4,
        interval -> Int4,
        timestamp -> Timestamptz,
        close_price -> Numeric,
        high_price -> Numeric,
        low_price -> Numeric,
        trade_volume -> Numeric,
        trade_count -> Int4,
    }
}

diesel::table! {
    personal_auth (account_id) {
        account_id -> Int4,
        id_card_front_url -> Text,
        id_card_back_url -> Text,
        real_name -> Text,
        id_number -> Text,
        bank_name -> Text,
        bank_account_number -> Text,
        bank_branch_name -> Nullable<Text>,
        review_status -> Text,
        submitted_at -> Timestamptz,
        verified_at -> Nullable<Timestamptz>,
        reject_reason -> Nullable<Text>,
    }
}

diesel::table! {
    smscodes (phone) {
        #[max_length = 20]
        phone -> Varchar,
        #[max_length = 10]
        sms_code -> Nullable<Varchar>,
        expire_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    system_config (id) {
        id -> Bool,
        fee_mode -> Text,
        trade_fee -> Numeric,
        withdraw_fee -> Numeric,
        vip_trade_fee -> Numeric,
        vip_withdraw_fee -> Numeric,
        issue_review -> Numeric,
        auth_review -> Numeric,
    }
}

diesel::table! {
    trade_orders (order_id) {
        order_id -> Int4,
        maker_id -> Int4,
        taker_id -> Nullable<Int4>,
        side -> Text,
        collection_id -> Int4,
        #[max_length = 6]
        serial_number -> Nullable<Varchar>,
        price -> Numeric,
        status -> Nullable<Text>,
        created_at -> Nullable<Timestamptz>,
        filled_at -> Nullable<Timestamptz>,
        fee -> Numeric,
    }
}

diesel::table! {
    transfers (transfer_id) {
        transfer_id -> Int4,
        sender_id -> Int4,
        receiver_id -> Int4,
        collection_id -> Int4,
        created_at -> Nullable<Timestamptz>,
        serial_numbers -> Nullable<Text>,
        estimated_value -> Nullable<Numeric>,
        quantity -> Nullable<Int4>,
    }
}

diesel::table! {
    vip_plans (plan_id) {
        plan_id -> Int4,
        name -> Text,
        duration_months -> Int4,
        base_price -> Numeric,
        promo_price -> Numeric,
        description -> Nullable<Text>,
    }
}

diesel::joinable!(assets -> accounts (owner_id));
diesel::joinable!(assets -> collections (collection_id));
diesel::joinable!(balance_logs -> accounts (account_id));
diesel::joinable!(boosts -> collections (collection_id));
diesel::joinable!(business_auth -> accounts (account_id));
diesel::joinable!(collections -> creations (collection_id));
diesel::joinable!(creations -> accounts (creator_id));
diesel::joinable!(personal_auth -> accounts (account_id));
diesel::joinable!(transfers -> collections (collection_id));

diesel::allow_tables_to_appear_in_same_query!(
    accounts,
    assets,
    balance_logs,
    banners,
    boost_plans,
    boosts,
    business_auth,
    collections,
    creations,
    kline_data,
    personal_auth,
    smscodes,
    system_config,
    trade_orders,
    transfers,
    vip_plans,
);
