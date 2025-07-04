use tokio::time::sleep;
use tokio_postgres::{NoTls, Client};
use chrono::Local;
use std::time::Duration;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:moomin@localhost/turbo",
        NoTls,
    ).await?;
    let client = Arc::new(client);

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });

    let client1 = Arc::clone(&client);
    tokio::spawn(async move {
        sync_24h_market_stats_every_10m(client1).await; 
    });

    let client2 = Arc::clone(&client);
    tokio::spawn(async move {
        update_user_asset_total_value_daily(client2).await;    
    });

    let client3 = Arc::clone(&client);
    tokio::spawn(async move {
        start_scheduled_assets_trading(client3).await;    
    });

    loop {
        sleep(Duration::from_secs(3600)).await;
    }
}

fn normalize(values: &[f64]) -> Vec<f64> {
    let min = values.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    values.iter().map(|&v| if max == min { 0.0 } else { (v - min) / (max - min) }).collect()
}

#[derive(Debug)]
struct Collection {
    collection_id: i32,
    volume_24h: f64,
    count_24h: f64,
    is_new: bool,
    change_ratio: f64,
    boost: f64,
}

async fn sync_24h_market_stats_every_10m(client: Arc<Client>) {
    loop {
        client.execute(r#"
            UPDATE collections c SET
                high_24h = agg.high_24h,
                low_24h = agg.low_24h,
                volume_24h = agg.volume_24h,
                count_24h = agg.count_24h,
                updated_at = NOW()
            FROM (    
                SELECT 
                    collection_id,
                    MAX(price) AS high_24h,
                    MIN(price) AS low_24h,
                    SUM(price) AS volume_24h,
                    COUNT(*) AS count_24h
                FROM trade_orders
                WHERE status = 'filled' AND filled_at >= NOW() - INTERVAL '24 hours' 
                GROUP BY collection_id 
            ) agg
            WHERE c.collection_id = agg.collection_id;"#, &[]
        ).await.expect("db error");

        //清理过期boost，更新boost值
        client.execute("DELETE FROM boosts WHERE expire_at < NOW();", &[]).await.expect("db error");
        client.execute("UPDATE collections SET boost = 0;", &[]).await.expect("db error");
        client.execute(r#"
            UPDATE collections c SET 
                boost = agg.boost_sum 
            FROM (
                SELECT 
                    collection_id,
                    SUM(score) AS boost_sum
                FROM boosts 
                GROUP BY collection_id 
            ) agg
            WHERE c.collection_id = agg.collection_id;
        "#, &[]).await.expect("db error");

        //计算推荐度并更新
        let collections: Vec<_> = client.query(r#"
            SELECT 
                collection_id,
                issue_price,
                trade_start_at,
                last_trade_price,
                volume_24h::float8 AS volume_24h,
                count_24h,
                (trade_start_at IS NOT NULL AND now() - trade_start_at <= interval '72 hours') AS is_new,
                ROUND((last_trade_price - issue_price) / NULLIF(issue_price, 0) * 100, 2)::float8 AS change_ratio,
                boost
            FROM collections JOIN creations ON collections.collection_id = creations.creation_id
            WHERE volume_24h IS NOT NULL;"#, &[]
        )
        .await
        .expect("db error")
        .into_iter()
        .map(|row| Collection {
            collection_id: row.get("collection_id"),
            volume_24h: row.get("volume_24h"),
            count_24h: row.get::<_, i32>("count_24h") as f64,
            is_new: row.get("is_new"),
            change_ratio: row.get("change_ratio"),
            boost: row.get::<_, i32>("boost") as f64,
        })
        .collect();
        
        let volumes: Vec<f64> = collections.iter().map(|c| c.volume_24h).collect();
        let counts: Vec<f64> = collections.iter().map(|c| c.count_24h).collect();
        let changes: Vec<f64> = collections.iter().map(|c| c.change_ratio).collect();
        let boosts: Vec<f64> = collections.iter().map(|c| c.boost).collect();
        let norm_volumes = normalize(&volumes);
        let norm_counts = normalize(&counts);
        let norm_changes = normalize(&changes);
        let norm_boosts = normalize(&boosts);        
        let recommend_scores: Vec<_> = collections.iter().enumerate().map(|(i, c)| {
            let norm_new = if c.is_new { 1.0 } else { 0.0 };
            let score =
                norm_volumes[i] * 0.3 +
                norm_counts[i]  * 0.2 +
                norm_changes[i] * 0.2 +
                norm_new        * 0.1 +
                norm_boosts[i]  * 0.2;
            (c.collection_id, score)
        }).collect();
        let values: Vec<String> = recommend_scores
            .iter()
            .map(|(id, score)| format!("({}, {})", id, score))
            .collect();
        let values_clause = values.join(", ");
        let update_sql = format!(
            "UPDATE collections AS c SET recommend_score = v.score
             FROM (VALUES {}) AS v(collection_id, score)
             WHERE c.collection_id = v.collection_id;",
            values_clause
        );
        client.execute(&update_sql, &[]).await.expect("db error");

        sleep(Duration::from_secs(600)).await; 
    }
}

async fn update_user_asset_total_value_daily(client: Arc<Client>) {
    loop {
        let now = Local::now();
        let next_midnight = now
            .date_naive()
            .succ_opt()
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
        let duration = (next_midnight - now.naive_local())
            .to_std()
            .unwrap_or(Duration::from_secs(0));
        sleep(duration).await;
        
        client.execute(r#"
            UPDATE accounts AS a
            SET total_asset_yesterday = sub.total, total_asset_today = sub.total 
            FROM (
                SELECT 
                    owner_id,
                    SUM(collections.last_trade_price) AS total
                FROM assets
                JOIN collections ON assets.collection_id = collections.collection_id
                GROUP BY owner_id
            ) AS sub
            WHERE a.user_id = sub.owner_id AND sub.total IS NOT NULL;"#, &[]
        ).await.expect("db error");

        //更新每个集合的当日基准价
        client.execute("UPDATE collections SET yesterday_price = last_trade_price;", &[]).await.expect("db error");
    }
}

async fn start_scheduled_assets_trading(client: Arc<Client>) {
    loop {
        let rows = client.query(r#"SELECT collection_id 
            FROM collections JOIN creations ON collections.collection_id = creations.creation_id 
            WHERE creations.trade_option = 'tradable' 
                AND creations.trade_start_at <= NOW() 
                AND creations.review_status = 'issued' 
                AND collections.is_tradable = FALSE;"#, &[]
        ).await.expect("db error");
        for row in rows {
            let collection_id: i32 = row.get("collection_id");
            println!("collection_id: {}", collection_id);

            client.execute(
                "UPDATE collections SET is_tradable = TRUE WHERE collection_id = $1",
                &[&collection_id]
            ).await.expect("db error");

            client.execute(r#"
                INSERT INTO trade_orders (maker_id, side, price, collection_id, serial_number)
                SELECT 
                    a.owner_id AS maker_id,
                    'sell' AS side,
                    c.issue_price AS price,
                    a.collection_id,
                    a.serial_number
                FROM assets a
                JOIN creations c ON a.collection_id = c.creation_id
                WHERE a.collection_id = $1
                AND a.source_type = 'issue';"#, 
                &[&collection_id]
            ).await.expect("db error");

            client.execute(
                "UPDATE assets SET is_locked = true WHERE collection_id = $1 AND source_type = 'issue'",
                &[&collection_id]
            ).await.expect("db error");

            println!("make sell orders done.");
        }
        sleep(Duration::from_secs(60)).await; 
    }
}
