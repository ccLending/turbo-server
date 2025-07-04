CREATE TABLE accounts (
    user_id SERIAL PRIMARY KEY,
    phone VARCHAR(20) UNIQUE NOT NULL,
    login_password TEXT NOT NULL,
    trade_password TEXT,
    avatar TEXT,
    nickname VARCHAR(30),
    is_verified BOOLEAN DEFAULT FALSE, 
    is_admin BOOLEAN DEFAULT FALSE,
    is_vip BOOLEAN DEFAULT FALSE,
    vip_expire_at TIMESTAMPTZ,
    account_type TEXT CHECK (account_type IN ('personal', 'business')),
    account_status TEXT CHECK (account_status IN ('active', 'locked', 'deleted')) DEFAULT 'active',
    
    total_asset_today NUMERIC(20, 2) DEFAULT 0,
    total_asset_yesterday NUMERIC(20, 2) DEFAULT 0,
    balance NUMERIC(20, 2) DEFAULT 0,
    frozen_amount NUMERIC(20, 2) DEFAULT 0,
    recharge_method TEXT,   -- alipay_withdraw
    withdraw_account TEXT,  -- wechat_withdraw
    
    sms_code VARCHAR(10),
    sms_code_expire_at TIMESTAMPTZ,
    login_retry_count INTEGER DEFAULT 0,
    unlock_time_if_locked TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    face_cert BOOLEAN DEFAULT FALSE
);
ALTER SEQUENCE accounts_user_id_seq RESTART WITH 1000001;

CREATE TABLE smscodes (
    phone VARCHAR(20) PRIMARY KEY,
    sms_code VARCHAR(10),
    expire_at TIMESTAMPTZ
);  

CREATE TABLE creations (
    creation_id SERIAL PRIMARY KEY,  
    creator_id INTEGER NOT NULL REFERENCES accounts(user_id), 
    title TEXT NOT NULL,
    cover_image TEXT,
    description TEXT,

    total_supply INTEGER NOT NULL CHECK (total_supply > 0),
    trade_option TEXT CHECK (trade_option IN ('non-tradable', 'tradable')) DEFAULT 'non-tradable',
    trade_start_at TIMESTAMPTZ,
    issue_price NUMERIC(10, 2),
    presale_enabled BOOLEAN DEFAULT FALSE,
    presale_ratio NUMERIC(5, 2) CHECK (presale_ratio BETWEEN 0 AND 100),
    presale_price NUMERIC(10, 2),
    
    review_status TEXT CHECK (review_status IN ('pending', 'rejected', 'approved', 'issued')) DEFAULT 'pending',
    submitted_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    rejected_at TIMESTAMPTZ,
    reject_reason TEXT,
    contract_address TEXT,
    issued_at TIMESTAMPTZ,
    presale_quantity INTEGER,
    presold_quantity INTEGER
);
ALTER SEQUENCE creations_creation_id_seq RESTART WITH 10000001;
CREATE INDEX idx_creations_creator_id ON creations (creator_id);

CREATE TABLE collections (
    collection_id INTEGER PRIMARY KEY REFERENCES creations(creation_id),
    last_trade_price NUMERIC(10, 2), 
    high_24h NUMERIC(10, 2),
    low_24h NUMERIC(10, 2), 
    volume_24h NUMERIC(14, 2),
    count_24h INTEGER,
    all_time_low NUMERIC(10, 2), 
    all_time_high NUMERIC(10, 2),
    all_time_volume NUMERIC(14, 2), 
    all_time_count INTEGER,
    market_cap NUMERIC(14, 2),
    is_tradable BOOLEAN DEFAULT FALSE,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    boost INTEGER DEFAULT 0,
    recommend_score NUMERIC(10, 8) DEFAULT 0.0,
    yesterday_price NUMERIC(10, 2)
);

CREATE TABLE boosts (
    boost_id SERIAL PRIMARY KEY, 
    collection_id INTEGER NOT NULL REFERENCES collections(collection_id),
    score INTEGER NOT NULL,
    expire_at TIMESTAMPTZ
);
CREATE INDEX idx_boosts_collection_id ON boosts (collection_id);

CREATE TABLE boost_plans (
    plan_id INTEGER PRIMARY KEY,
    score INTEGER NOT NULL,
    duration_hours INTEGER NOT NULL,         
    price NUMERIC(10, 2) NOT NULL   
);

CREATE TABLE banners (
    banner_id SERIAL PRIMARY KEY,
    banner_url TEXT,
    jump_type TEXT CHECK (jump_type IN ('internal', 'external')),
    jump_url TEXT,
    collection_id INTEGER
);

CREATE TABLE assets (
    asset_id SERIAL PRIMARY KEY, 
    asset_name TEXT,
    collection_id INTEGER NOT NULL REFERENCES collections(collection_id),
    serial_number VARCHAR(6),
    nft_address TEXT,
    is_locked BOOLEAN DEFAULT FALSE,
    last_price NUMERIC(10, 2),  
    owner_id INTEGER NOT NULL REFERENCES accounts(user_id),
    source_type TEXT CHECK (source_type IN ('trade', 'issue', 'transfer', 'presale')) DEFAULT 'trade',
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
ALTER SEQUENCE assets_asset_id_seq RESTART WITH 100000001;
CREATE INDEX idx_assets_owner_id ON assets (owner_id);
CREATE INDEX idx_assets_collection_serial ON assets (collection_id, serial_number);

CREATE TABLE transfers (
    transfer_id SERIAL PRIMARY KEY, 
    sender_id INTEGER NOT NULL REFERENCES accounts(user_id),
    receiver_id INTEGER NOT NULL REFERENCES accounts(user_id),
    collection_id INTEGER NOT NULL REFERENCES collections(collection_id),
    serial_numbers TEXT,
    estimated_value NUMERIC(10, 2) DEFAULT 0.0,
    quantity INTEGER,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_transfers_sender_id ON transfers (sender_id);
CREATE INDEX idx_transfers_collection_id ON transfers (collection_id);

CREATE TABLE trade_orders (
    order_id SERIAL PRIMARY KEY,
    maker_id INTEGER NOT NULL,  
    taker_id INTEGER,          
    side TEXT NOT NULL CHECK (side IN ('buy', 'sell')),
    collection_id INTEGER NOT NULL,
    serial_number VARCHAR(6), 
    price NUMERIC(10, 2) NOT NULL,
    status TEXT CHECK (status IN ('open', 'filled', 'cancelled')) DEFAULT 'open',
    fee NUMERIC(10, 2) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    filled_at TIMESTAMPTZ 
);
ALTER SEQUENCE trade_orders_order_id_seq RESTART WITH 1000001;
CREATE INDEX idx_trade_orders_maker_id ON trade_orders (maker_id);
CREATE INDEX idx_trade_orders_taker_id ON trade_orders (taker_id);
CREATE INDEX idx_trade_orders_collection_id ON trade_orders (collection_id);

CREATE TABLE kline_data (
    collection_id INTEGER NOT NULL,
    interval INTEGER NOT NULL CHECK(interval IN (1, 4, 12, 24)), -- 时间粒度 1h 4h 12h 1d
    timestamp TIMESTAMPTZ NOT NULL,         -- 行情时间戳，该粒度的起始时间

    close_price NUMERIC(10, 2) NOT NULL,    -- 收盘价 
    high_price NUMERIC(10, 2) NOT NULL, 
    low_price NUMERIC(10, 2) NOT NULL,  
    trade_volume NUMERIC(14, 2) NOT NULL,   -- 交易量         
    trade_count INTEGER NOT NULL,           -- 交易笔数    
    -- 联合主键：确保 collection_id + interval + timestamp 唯一，防止重复插入
    PRIMARY KEY (collection_id, interval, timestamp)
);

CREATE TABLE personal_auth (
    account_id INTEGER PRIMARY KEY REFERENCES accounts(user_id),
    id_card_front_url TEXT NOT NULL,
    id_card_back_url TEXT NOT NULL,
    real_name TEXT NOT NULL,
    id_number TEXT NOT NULL,
    bank_name TEXT NOT NULL,
    bank_account_number TEXT NOT NULL,
    bank_branch_name TEXT,
    review_status TEXT NOT NULL CHECK (review_status IN ('pending', 'rejected', 'approved')) DEFAULT 'pending',
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    verified_at TIMESTAMPTZ,
    reject_reason TEXT
);

CREATE TABLE business_auth (
    account_id INTEGER PRIMARY KEY REFERENCES accounts(user_id),
    business_license_url TEXT NOT NULL,
    company_name TEXT NOT NULL,
    social_credit_code TEXT NOT NULL,
    bank_name TEXT NOT NULL,
    bank_account_number TEXT NOT NULL,
    bank_branch_name TEXT,
    review_status TEXT NOT NULL CHECK (review_status IN ('pending', 'rejected', 'approved')) DEFAULT 'pending',
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    verified_at TIMESTAMPTZ,
    reject_reason TEXT
);

CREATE TABLE vip_plans (
    plan_id INTEGER PRIMARY KEY,
    name TEXT NOT NULL, 
    duration_months INTEGER NOT NULL,           -- 月数
    base_price NUMERIC(10, 2) NOT NULL,         -- 原价
    promo_price NUMERIC(10, 2) NOT NULL,         -- 促销价
    description TEXT
);

CREATE TABLE balance_logs (
    log_id SERIAL PRIMARY KEY, 
    account_id INTEGER NOT NULL REFERENCES accounts(user_id),
    amount NUMERIC(10, 2) NOT NULL,         -- 本次变动金额（正表示入账，负表示出账）
    balance_after NUMERIC(10, 2) NOT NULL,
    opt_type TEXT NOT NULL CHECK (
        opt_type IN (
            'deposit',         -- 充值
            'withdrawal',      -- 提现
            'buy',             -- 买入
            'sell',            -- 卖出
            'check',           -- 审核
            'fee',             -- 手续费
            'refund',          -- 退款
            'reward'           -- 奖励
        )
    ),
    memo TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_balance_logs_account_time ON balance_logs(account_id, created_at DESC);

CREATE TABLE system_config (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE,    -- 固定为单行（true），确保只有一条记录
    
    fee_mode TEXT NOT NULL CHECK (fee_mode IN ('percentage', 'fixed')),
    trade_fee NUMERIC(10, 2) NOT NULL DEFAULT 0,
    withdraw_fee NUMERIC(10, 2) NOT NULL DEFAULT 0,           
    vip_trade_fee NUMERIC(10, 2) NOT NULL DEFAULT 0,          
    vip_withdraw_fee NUMERIC(10, 2) NOT NULL DEFAULT 0,
    issue_review NUMERIC(10, 2) NOT NULL DEFAULT 0,         -- 发行审核费
    auth_review NUMERIC(10, 2) NOT NULL DEFAULT 0           -- 认证审核费
);

