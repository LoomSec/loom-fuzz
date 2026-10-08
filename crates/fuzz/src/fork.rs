//! on-demand fork 执行（issue #21 重写）：revm 42 `AlloyDB` 远程状态
//! + `CacheDB` 本地 overlay——与 anvil/Foundry 同款叠层架构。
//!
//! - **读路径**：每 run 的 `CacheDB` miss → [`ForkDb`]（共享内存缓存，
//!   read-through）→ `AlloyDB`（HTTP JSON-RPC，pin block）。单阶段：
//!   fuzz 循环任何深度都能拿真状态，无物化/收敛问题（PR #23 两阶段
//!   方案废弃）。
//! - **写路径**：`CacheDB` 本地写——prestate 槽照旧、deployment etch
//!   （"fork 后部署攻击合约"）overlay 其上，不回写链。
//! - **pin block 确定性**：`ForkConfig.block_number` 在 CLI 侧把
//!   "latest" 先解析成具体块号（eth_blockNumber）；同 (url, block)
//!   的 [`ForkDb`] 进程级共享（含 tokio runtime），二次运行走缓存。
//! - **认证**：env `BLOCKMACHINE_API_KEY` 非空 = reqwest default
//!   header `Authorization: Bearer`；空 = keyless 直连。
//!
//! **执行地址归位**：fork 态应在 `--contract-addr <真实地址>` 上执行
//! （探测/执行同一地址，否则合约自身存储错位）——CLI 层强制。

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use alloy_eips::BlockId;
use alloy_provider::{network::Ethereum, Provider, RootProvider};
use alloy_rpc_client::ClientBuilder;
use revm::database::{AlloyDB, AlloyDBError};
use revm::database_interface::{DatabaseRef, WrapDatabaseAsync};
use revm::primitives::{Address, StorageKey, StorageValue, B256};
use revm::state::{AccountInfo, Bytecode};
use serde::{Deserialize, Serialize};

/// fork 配置（pin block；serde 进 poc.json 供 replay 重建）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkConfig {
    pub rpc_url: String,
    /// pin 块号（"latest" 已在 CLI 解析成具体值——确定性前提）。
    pub block_number: u64,
}

type HttpProvider = RootProvider<Ethereum>;
// 注：Ethereum 网络，transport 已装箱进 RootProvider。

/// ForkDb：共享内存缓存（read-through/write-through）包一层
/// AlloyDB（异步 RPC，经 WrapDatabaseAsync 同步化）。
pub struct ForkDb {
    alloy: WrapDatabaseAsync<AlloyDB<Ethereum, HttpProvider>>,
    cache: Arc<Mutex<ForkCacheMap>>,
}

#[derive(Debug, Default)]
struct ForkCacheMap {
    /// (address) → (balance, nonce, code)。None = 链上不存在。
    accounts: BTreeMap<Address, Option<AccountInfo>>,
    storage: BTreeMap<(Address, StorageKey), StorageValue>,
}

/// 构建 HTTP provider：reqwest client（keyless 或 Bearer 头），
/// 显式 RootProvider（绕开 fillers 类型，AlloyDB 只要 Provider）。
fn build_provider(rpc_url: &str, api_key: &str) -> Result<HttpProvider, String> {
    let url: reqwest::Url = rpc_url
        .parse()
        .map_err(|e| format!("--fork-url 非法: {e}"))?;
    let client = if api_key.is_empty() {
        reqwest::Client::new()
    } else {
        let mut h = reqwest::header::HeaderMap::new();
        if let Ok(v) = reqwest::header::HeaderValue::from_str(&format!("Bearer {api_key}")) {
            h.insert(reqwest::header::AUTHORIZATION, v);
        }
        reqwest::Client::builder()
            .default_headers(h)
            .build()
            .map_err(|e| format!("reqwest client 构建失败: {e}"))?
    };
    let rpc_client = ClientBuilder::default().http_with_client(client, url);
    Ok(RootProvider::new(rpc_client))
}

/// 进程级共享表：同 (rpc_url, block) 复用（含 tokio runtime——
/// 每 execute 新建 runtime 的线程开销不可接受）。
type SharedTable = BTreeMap<(String, u64), Arc<ForkDb>>;
static SHARED: OnceLock<Mutex<SharedTable>> = OnceLock::new();

impl ForkDb {
    /// 构建（或复用）一个 pin block 的 fork 数据库。
    pub fn shared(cfg: &ForkConfig, api_key: &str) -> Result<Arc<ForkDb>, String> {
        let table = SHARED.get_or_init(|| Mutex::new(BTreeMap::new()));
        let mut table = table.lock().map_err(|e| format!("fork 表锁: {e}"))?;
        let key = (cfg.rpc_url.clone(), cfg.block_number);
        if let Some(db) = table.get(&key) {
            return Ok(db.clone());
        }
        let provider = build_provider(&cfg.rpc_url, api_key)?;
        let alloy = AlloyDB::new(provider, BlockId::from(cfg.block_number));
        let runtime =
            tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime 构建失败: {e}"))?;
        let db = Arc::new(ForkDb {
            alloy: WrapDatabaseAsync::with_runtime(alloy, runtime),
            cache: Arc::new(Mutex::new(ForkCacheMap::default())),
        });
        table.insert(key, db.clone());
        Ok(db)
    }
}

impl DatabaseRef for ForkDb {
    type Error = AlloyDBError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        if let Some(hit) = self
            .cache
            .lock()
            .expect("fork 缓存锁")
            .accounts
            .get(&address)
        {
            return Ok(hit.clone());
        }
        let info = self.alloy.basic_ref(address)?;
        if let Some(info) = &info {
            self.cache
                .lock()
                .expect("fork 缓存锁")
                .accounts
                .insert(address, Some(info.clone()));
        }
        Ok(info)
    }

    fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        // 与 AlloyDB 同约定：code 随 basic_ref 加载，不走 hash 路径。
        unreachable!("code 随 basic_ref 加载")
    }

    fn storage_ref(
        &self,
        address: Address,
        index: StorageKey,
    ) -> Result<StorageValue, Self::Error> {
        if let Some(hit) = self
            .cache
            .lock()
            .expect("fork 缓存锁")
            .storage
            .get(&(address, index))
        {
            return Ok(*hit);
        }
        let value = self.alloy.storage_ref(address, index)?;
        self.cache
            .lock()
            .expect("fork 缓存锁")
            .storage
            .insert((address, index), value);
        Ok(value)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.alloy.block_hash_ref(number)
    }
}

/// 通用应答 runtime 构造器（**零签名感知**，ABI 右对齐标准返回）：
/// 任何 call 返回固定 32 字节字。逐指令：PUSH32 word; PUSH1 0;
/// MSTORE; PUSH1 32; PUSH1 0; RETURN。
pub fn responder_runtime(word: [u8; 32]) -> Vec<u8> {
    let mut code = Vec::with_capacity(38);
    code.push(0x7f);
    code.extend_from_slice(&word);
    code.extend_from_slice(&[0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]);
    code
}

/// responder 特例：任何 call 返回 msg.sender（ABI 右对齐——Visor
/// owner 检查要标准地址字，左对齐是旧 PR 踩过的坑）。逐指令：
/// CALLER; PUSH1 0; MSTORE; PUSH1 32; PUSH1 0; RETURN。
pub fn responder_runtime_sender() -> Vec<u8> {
    vec![
        0x33, // CALLER
        0x60, 0x00, // PUSH1 0
        0x52, // MSTORE：mem[0..32] = 0x00…00<caller>（右对齐）
        0x60, 0x20, // PUSH1 32
        0x60, 0x00, // PUSH1 0
        0xf3, // RETURN
    ]
}

/// CLI 解析 --fork-block：数字原样；"latest" 经一次 RPC 解析成具体
/// 块号（pin block = 确定性前提）。
pub fn pin_block(rpc_url: &str, api_key: &str, block: &str) -> Result<u64, String> {
    if block != "latest" {
        return block
            .parse()
            .map_err(|_| format!("--fork-block 非法（数字/latest）: {block:?}"));
    }
    let provider = build_provider(rpc_url, api_key)?;
    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
    rt.block_on(provider.get_block_number())
        .map_err(|e| format!("eth_blockNumber 失败: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn responder_runtimes_return_right_aligned_word() {
        let word = [0xaau8; 32];
        let code = responder_runtime(word);
        // PUSH32 + 32B + PUSH1/MSTORE/PUSH1/PUSH1/RETURN（8B）。
        assert_eq!(code.len(), 41);
        assert_eq!(code[0], 0x7f);
        assert_eq!(&code[1..33], &word);

        let sender = responder_runtime_sender();
        assert_eq!(
            sender,
            vec![0x33, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]
        );
    }

    /// fork plumbing 最小验证（LOOM_FUZZ_FORK_TEST=1 才跑）：keyless
    /// pin block + 远程读一个主网账户（WETH 有码）。
    #[test]
    fn fork_keyless_connectivity() {
        if std::env::var("LOOM_FUZZ_FORK_TEST").ok().as_deref() != Some("1") {
            eprintln!("fork 连通性测试跳过（LOOM_FUZZ_FORK_TEST 未设）");
            return;
        }
        let block = pin_block("https://rpc-eth.blockmachine.io", "", "latest")
            .expect("eth_blockNumber keyless");
        let db = ForkDb::shared(
            &ForkConfig {
                rpc_url: "https://rpc-eth.blockmachine.io".to_string(),
                block_number: block,
            },
            "",
        )
        .expect("ForkDb 构建");
        let weth = revm::primitives::Address::from_slice(&[
            0xc0, 0x2a, 0xaa, 0x39, 0xb2, 0x23, 0xfe, 0x8d, 0x0a, 0x0e, 0x5c, 0x4f, 0x27, 0xea,
            0xd9, 0x08, 0x3c, 0x75, 0x6c, 0xc2,
        ]);
        let info = db.basic_ref(weth).expect("basic_ref");
        let info = info.expect("WETH 账户存在");
        assert!(
            !info.code.as_ref().is_some_and(|c| c.is_empty()),
            "WETH 有码"
        );
    }

    #[test]
    fn fork_config_serde_roundtrip() {
        let cfg = ForkConfig {
            rpc_url: "https://example".to_string(),
            block_number: 42,
        };
        let json = serde_json::to_vec(&cfg).unwrap();
        let back: ForkConfig = serde_json::from_slice(&json).unwrap();
        assert_eq!(cfg, back);
        let mut addr = [0u8; 20];
        addr[19] = 0xde;
        let d = crate::Deployment {
            address: addr,
            runtime: vec![0x33],
        };
        assert_eq!(d.address[19], 0xde);
    }
}
