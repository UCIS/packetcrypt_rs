// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use crate::protocol::{BlockInfo, MasterConf};
use crate::util;
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::sync::broadcast::Receiver;
use tokio::sync::RwLock;
use anyhow::{format_err, Result};
use reqwest::header::{HeaderMap, HeaderValue};
use uuid::Uuid;

#[derive(Debug)]
pub struct PoolClientM {
    mc: Option<MasterConf>,
    chain: HashMap<i32, BlockInfo>,
}

#[derive(Debug)]
pub struct PoolClientS {
    m: RwLock<PoolClientM>,
    pub url: String,
    poll_seconds: u64,
    notify: broadcast::Sender<PoolUpdate>,
    history_depth: i32,
    client: reqwest::Client,
    download_blkinfo: bool,
}
pub type PoolClient = Arc<PoolClientS>;

pub fn new(url: &str, history_depth: i32, poll_seconds: u64, download_blkinfo: bool) -> PoolClient {
    let (tx, _) = broadcast::channel::<PoolUpdate>(32);

    let mut client_headers = HeaderMap::new();
    client_headers.insert("x-pc-sid", HeaderValue::from_str(&Uuid::new_v4().simple().to_string()).unwrap());

    Arc::new(PoolClientS {
        m: RwLock::new(PoolClientM {
            mc: None,
            chain: HashMap::new(),
        }),
        poll_seconds,
        url: String::from(url),
        notify: tx,
        history_depth,
        client: reqwest::ClientBuilder::new()
            .user_agent(format!("packetcrypt_rs {}", util::version()))
            .default_headers(client_headers)
            .build()
            .unwrap(),
        download_blkinfo: download_blkinfo,
    })
}

#[derive(Clone)]
pub struct PoolUpdate {
    pub conf: MasterConf,
    pub update_blocks: Vec<BlockInfo>,
}

pub async fn update_chan(pcli: &PoolClient) -> Receiver<PoolUpdate> {
    pcli.notify.subscribe()
}

fn fmt_blk(hash: &[u8; 32], height: i32) -> String {
    format!("{} @ {}", hex::encode(&hash[..]), height)
}

async fn get_url_text(pcli: &PoolClient, url: &str) -> Result<String> {
    let res = pcli.client.get(url).send().await?;
    match res.status() {
        reqwest::StatusCode::OK => Ok(res.text().await?),
        st => Err(format_err!("Status code was {:?}", st)),
    }
}

async fn discover_block(pcli: &PoolClient, height: i32, hash: &[u8; 32], blkinfo_url: &str) -> Option<BlockInfo> {
    if let Some(bi) = pcli.m.read().await.chain.get(&height) {
        if &bi.header.hash == hash {
            debug!("We already know about block [{}]", fmt_blk(hash, height));
            return None;
        } else {
            // we have an entry for this block, but it is incorrect (rollback)
            info!(
                "ROLLBACK [{}] incorrect, replace with [{}]",
                fmt_blk(&bi.header.hash, height),
                fmt_blk(hash, height)
            );
        }
    } else {
        //debug!("New block [{}]", fmt_blk(&hash, height));
    }
    let url = format!("{}/blkinfo_{}.json", blkinfo_url, hex::encode(&hash[..]));
    loop {
        let text = match get_url_text(pcli, &url).await {
            Err(e) => {
                warn!(
                    "Failed to make request to {} because {:?}",
                    &url, e
                );
                return None;
            }
            Ok(r) => r,
        };
        let bi = match serde_json::from_str::<BlockInfo>(text.as_str()) {
            Err(e) => {
                info!("Failed to deserialize block info {:?} {:?}", text, e);
                return None;
            }
            Ok(r) => r,
        };
        info!(
            "Discovered block [{}]",
            fmt_blk(&bi.header.hash, bi.header.height)
        );
        pcli.m.write().await.chain.insert(bi.header.height, bi);
        return Some(bi);
    }
}

// This takes a newly discovered block and returns a vector of blocks which have
// been changed. It calls the pool master iteratively in order to back-fill any
// blocks which are incorrect and it updates the local state appropriately.
async fn discover_blocks(pcli: &PoolClient, height: i32, hash: &[u8; 32], blkinfo_url: &str) -> Vec<BlockInfo> {
    let mut out: Vec<BlockInfo> = Vec::new();
    if !pcli.download_blkinfo {
        return out;
    }
    let mut xhash = *hash;
    let mut xheight = height;
    loop {
        if let Some(bi) = discover_block(pcli, xheight, &xhash, &blkinfo_url).await {
            if bi.header.height <= height - pcli.history_depth {
                // We've backfilled enough history
                return out;
            }
            xhash = bi.header.previousblockhash;
            xheight -= 1;
            out.push(bi);
        } else {
            return out;
        };
    }
}

async fn cfg_loop(pcli: &PoolClient) {
    loop {
        let url = format!("{}/config.json", pcli.url);
        let text = match get_url_text(pcli, &url).await {
            Err(e) => {
                warn!(
                    "Failed to make request to {} because {:?} retry in 5 seconds",
                    &url, e
                );
                util::sleep_ms(5000).await;
                continue;
            }
            Ok(r) => r,
        };
        let conf = match serde_json::from_str::<MasterConf>(text.as_str()) {
            Err(e) => {
                info!("Failed to deserialize master conf {:?} {:?}", text, e);
                util::sleep_ms(5000).await;
                continue;
            }
            Ok(r) => r,
        };
        let tip_hash = if let Some(tip_hash) = conf.tip_hash {
            tip_hash
        } else {
            error!("Pool missing tipHash, this pool is too old to mine with");
            util::sleep_ms(5000).await;
            continue;
        };
        if {
            let pcr = pcli.m.read().await;
            if let Some(mcx) = &pcr.mc {
                !mcx.eq(&conf)
            } else {
                if pcr.mc == None {
                    info!("Got master config");
                } else {
                    info!("Change of master config");
                }
                true
            }
        } {
            let blkinfo_url = conf.blkinfo_url.clone().unwrap_or(pcli.url.clone());
            let update_blocks = discover_blocks(pcli, conf.current_height - 1, &tip_hash, &blkinfo_url).await;
            let mut pc = pcli.m.write().await;
            pc.mc = Some(conf.clone());
            if let Err(_) = pcli.notify.send(PoolUpdate {
                conf,
                update_blocks,
            }) {
                info!("Failed to send conf update to channel");
            }
        }
        util::sleep_ms(1_000 * pcli.poll_seconds).await;
    }
}

pub async fn start(pcli: &PoolClient) {
    async_spawn!(pcli, {
        cfg_loop(&pcli).await;
    });
}
