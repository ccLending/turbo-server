use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    signature::{Keypair, Signer, read_keypair_file},
    transaction::Transaction,
    pubkey::Pubkey,
    system_program, sysvar,
};
use mpl_token_metadata::{
    accounts::{Metadata, MasterEdition},
    instructions::{CreateV1, CreateV1InstructionArgs, VerifyCollectionV1},
    types::{Creator, Collection, TokenStandard, PrintSupply},
};
use serde::{Serialize, Deserialize};
use reqwest::{Client, multipart};
use std::{
    fs::File, 
    path::Path, 
    io::{Read, Write}, 
    error::Error, 
    time::Duration,
    env,
};
use tokio_postgres::NoTls;
use dotenvy::dotenv;
use chrono::Utc;

const MAX_RETRIES: u32 = 3;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    //let rpc_url = "https://rpc.ankr.com/solana_devnet/bcc84106cf48bdd048b6e5e44a10d4e2645ad0dbd6d14cebdd399b8f5b104e43";
    let rpc_url = "https://devnet.helius-rpc.com/?api-key=9d49e5ae-e8a0-4ad1-af21-ac4f1b9f3a19";
    let rpc = RpcClient::new(rpc_url.to_string());
    let payer = read_keypair_file("/root/.config/solana/id.json").expect("Could not read keypair");

    dotenv().ok();
    let db_url = env::var("DATABASE_URL")?;
    let (client, connection) = tokio_postgres::connect(&db_url, NoTls).await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("数据库连接错误: {}", e);
        }
    });

    loop {
        let rows = client.query(
            "SELECT creation_id, title, cover_image, description, total_supply, creator_id FROM creations WHERE review_status = 'approved'",
            &[]
        ).await?;

        for row in rows {
            let creation_id: i32 = row.get("creation_id");
            let title: String = row.get("title");
            let cover_image: String = row.get("cover_image");
            let cover_image = format!("/root/turbo{}", cover_image);
            let description: String = row.get("description");
            let total_supply: i32 = row.get("total_supply");
            let creator_id: i32 = row.get("creator_id");
            println!("process create_id: {}, title: {}, supply: {} ...", creation_id, title, total_supply);

            if let Some(cid) = upload_with_retry(&cover_image).await {
                let image_uri = format!("https://gateway.pinata.cloud/ipfs/{}", cid);
                let filename = format!("./metadata/{}.json", creation_id);
                let _ = build_metadata_json(&filename, &title, &description, &image_uri, &payer.pubkey());
                if let Some(cid) = upload_with_retry(&filename).await {
                    let uri = format!("https://gateway.pinata.cloud/ipfs/{}", cid);
                    if let Some(collection) = mint_collection_with_retry(&rpc, &payer, &title, &uri).await {
                        client.execute(
                            "INSERT INTO collections (collection_id) VALUES ($1)",
                            &[&creation_id]
                        ).await?;

                        for i in 1..=total_supply {
                            let serial_number = format!("{:03}", i);
                            let name = format!("{} #{}", title, serial_number);    
                            let filename = format!("./metadata/{}-{}.json", creation_id, serial_number);
                            let _ = build_metadata_json(&filename, &name, &description, &image_uri, &payer.pubkey());
                            if let Some(cid) = upload_with_retry(&filename).await {
                                let uri = format!("https://gateway.pinata.cloud/ipfs/{}", cid);
                                if let Some(mint) = mint_nft_with_retry(&rpc, &payer, &name, &uri, &collection).await {
                                    client.execute(
                                        "INSERT INTO assets (asset_name, collection_id, nft_address, serial_number, owner_id, source_type) VALUES ($1, $2, $3, $4, $5, 'issue')",
                                        &[&name, &creation_id, &mint.to_string(), &serial_number, &creator_id]
                                    ).await?;
                                }
                            }
                        }

                        client.execute(
                            "UPDATE creations SET review_status = 'issued', contract_address = $1, issued_at = $2 WHERE creation_id = $3",
                            &[&collection.to_string(), &Utc::now(), &creation_id]
                        ).await?;
                    }  
                }
            }
            println!("process creation {} {} done!", creation_id, title);
        }
        //每分钟检测一次
        tokio::time::sleep(Duration::from_secs(1 * 60)).await;  
    }
}

async fn upload_with_retry(file_path: &str) -> Option<String> {
    for attempt in 1..=MAX_RETRIES {
        match upload_to_pinata(file_path).await {
            Ok(cid) => {
                println!("upload-ipft success {}", file_path);
                return Some(cid);
            }
            Err(e) => {
                println!("upload-ipfs failed {}, {}", file_path, e);
                if attempt < MAX_RETRIES {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }
    println!("upload-ipfs 放弃: {}", file_path);
    None
}

#[derive(Deserialize)]
struct PinResponse {
    #[serde(rename = "IpfsHash")]
    ipfs_hash: String,
}

async fn upload_to_pinata(file_path: &str) -> Result<String, Box<dyn Error>> {
    let url = "https://api.pinata.cloud/pinning/pinFileToIPFS";
    let api_key = "db79b14205a2fa90489c";
    let api_secret = "322ba3b5ed0483d400984c4a726220d06dea9501008c3d1fc733a0df56cd23cd";

    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    let file_name = Path::new(file_path).file_name().unwrap().to_str().unwrap();
    let part = multipart::Part::bytes(buffer).file_name(file_name.to_string());
    let form = multipart::Form::new().part("file", part);

    let client = Client::new();
    let res = client
        .post(url)
        .header("pinata_api_key", api_key)
        .header("pinata_secret_api_key", api_secret)
        .multipart(form)
        .send()
        .await?;
    let json: PinResponse = res.json().await?;
    Ok(json.ipfs_hash)
}

async fn mint_nft_with_retry(
    client: &RpcClient, 
    payer: &Keypair,
    name: &str,
    uri: &str,
    collection: &Pubkey,
) -> Option<Pubkey> {
    for attempt in 1..=MAX_RETRIES {
        match mint_nft(client, payer, name, uri, collection).await {
            Ok(mint) => {
                println!("mint nft {} success: {}", name, mint);
                return Some(mint);
            }
            Err(e) => {
                println!("mint nft {} failed: {}", name, e);
                if attempt < MAX_RETRIES {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }
    println!("mint nft {} 放弃", name);
    None
}

async fn mint_nft(
    client: &RpcClient, 
    payer: &Keypair, 
    name: &str,
    uri: &str,
    collection: &Pubkey,
) -> Result<Pubkey, Box<dyn Error>> {
    let mint = Keypair::new();
    let metadata = Metadata::find_pda(&mint.pubkey()).0;
    let master_edition  = MasterEdition::find_pda(&mint.pubkey()).0;
    let collection_mint = collection.clone();
    let collection_metadata = Some(Metadata::find_pda(&collection_mint).0);
    let collection_master_edition = Some(MasterEdition::find_pda(&collection_mint).0);

    let args = CreateV1InstructionArgs {
        name: String::from(name),
        uri: String::from(uri),
        symbol: String::from(""),
        seller_fee_basis_points: 100,
        primary_sale_happened: false,
        is_mutable: true,
        creators: Some(vec![Creator {
            address: payer.pubkey(),
            verified: true,
            share: 100,
        }]),
        token_standard: TokenStandard::ProgrammableNonFungible,
        collection: Some(Collection {
            verified: false,
            key: collection_mint,
        }),
        collection_details: None,
        decimals: Some(0),
        print_supply: Some(PrintSupply::Zero),
        rule_set: None,
        uses: None,
    };
    let create_ix = CreateV1 {
        metadata,
        master_edition: Some(master_edition),
        mint: (mint.pubkey(), true),
        authority: payer.pubkey(),
        update_authority: (payer.pubkey(), true),
        payer: payer.pubkey(),
        spl_token_program: Some(spl_token::ID),
        system_program: system_program::ID,
        sysvar_instructions: sysvar::instructions::ID,
    }
    .instruction(args);

    let verify_ix = VerifyCollectionV1 {
        authority: payer.pubkey(),
        delegate_record: None,
        metadata,
        collection_mint,
        collection_metadata,
        collection_master_edition,
        system_program: system_program::ID,
        sysvar_instructions: sysvar::instructions::ID,
    }
    .instruction();

    let tx = Transaction::new_signed_with_payer(
        &[create_ix, verify_ix],
        Some(&payer.pubkey()),
        &[&payer, &mint],
        client.get_latest_blockhash().await?,
    );
    let _ = client.send_and_confirm_transaction(&tx).await?;
    Ok(mint.pubkey())
}

async fn mint_collection_with_retry(
    client: &RpcClient, 
    payer: &Keypair,
    name: &str,
    uri: &str,
) -> Option<Pubkey> {
    for attempt in 1..=MAX_RETRIES {
        match mint_collection(client, payer, name, uri).await {
            Ok(collection) => {
                println!("mint collection {} success: {}", name, collection);
                return Some(collection);
            }
            Err(e) => {
                println!("mint collection {} failed: {}", name, e);
                if attempt < MAX_RETRIES {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }
    println!("mint collection {} 放弃", name);
    None
}

async fn mint_collection(
    client: &RpcClient, 
    payer: &Keypair,
    name: &str,
    uri: &str,
) -> Result<Pubkey, Box<dyn Error>> {
    let mint = Keypair::new();
    let (metadata, _) = Metadata::find_pda(&mint.pubkey());
    let (master_edition, _) = MasterEdition::find_pda(&mint.pubkey());

    let args = CreateV1InstructionArgs {
        name: String::from(name),
        uri: String::from(uri),
        symbol: String::from(""),
        seller_fee_basis_points: 100,
        primary_sale_happened: false,
        is_mutable: true,
        creators: Some(vec![Creator {
            address: payer.pubkey(),
            verified: true,
            share: 100,
        }]),
        token_standard: TokenStandard::ProgrammableNonFungible,
        collection: None,
        collection_details: None,
        decimals: Some(0),
        print_supply: Some(PrintSupply::Zero),
        rule_set: None,
        uses: None,
    };
    let create_ix = CreateV1 {
        metadata,
        master_edition: Some(master_edition),
        mint: (mint.pubkey(), true),
        authority: payer.pubkey(),
        update_authority: (payer.pubkey(), true),
        payer: payer.pubkey(),
        spl_token_program: Some(spl_token::ID),
        system_program: system_program::ID,
        sysvar_instructions: sysvar::instructions::ID,
    }
    .instruction(args);

    let tx = Transaction::new_signed_with_payer(
        &[create_ix],
        Some(&payer.pubkey()),
        &[&payer, &mint],
        client.get_latest_blockhash().await?,
    );
    let _ = client.send_and_confirm_transaction(&tx).await?;
    Ok(mint.pubkey())
}

fn build_metadata_json(filename: &str, name: &str, description: &str, image: &str, creator: &Pubkey) -> std::io::Result<()> {
    #[derive(Serialize)]
    struct Metadata {
        name: String,
        symbol: String,
        description: String,
        image: String,
        external_url: String,
        seller_fee_basis_points: u32,
        properties: Properties,
    }
    #[derive(Serialize)]
    struct Properties {
        files: Vec<FileInfo>,
        category: String,
        creators: Vec<Creator>,
    }
    #[derive(Serialize)]
    struct FileInfo {
        uri: String,
        #[serde(rename = "type")]
        file_type: String,
    }
    #[derive(Serialize)]
    struct Creator {
        address: String,
        share: u32,
    }

    let metadata = Metadata {
        name: name.to_string(),
        symbol: "".to_string(),
        description: description.to_string(),
        image: image.to_string(),
        external_url: "https://turbonft.com".to_string(),
        seller_fee_basis_points: 100,
        properties: Properties {
            files: vec![FileInfo {
                uri: image.to_string(),
                file_type: "image/png".to_string(),
            }],
            category: "image".to_string(),
            creators: vec![Creator {
                address: creator.to_string(),
                share: 100,
            }],
        },
    };

    let json = serde_json::to_string_pretty(&metadata).unwrap();
    let mut file = File::create(filename)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

