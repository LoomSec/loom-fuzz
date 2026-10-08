//! fork 链上状态的 serde 形态与 hydration（issue #21）。
//!
//! `fetch-state`（CLI 子命令）两阶段物化的产物 state.json：
//! 探测执行（空库）收集触及地址/槽集 → JSON-RPC 批量拉取
//! （pin block）→ hydration 后再探测一轮（迭代加深 ≤3 轮或
//! 集合不变收敛）→ 落盘。执行器 `--state` 加载本文件 hydration
//! 进 CacheDB；prestate 槽与 deployment 部署照旧 overlay 其上。
//! **不存 key**。

use std::collections::BTreeMap;
use std::path::Path;

use alloy_primitives::U256;
use serde::{Deserialize, Serialize};

/// state.json 顶层。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkStateFile {
    /// 地址（0x-hex，40 字符）→ 账户。
    pub addresses: BTreeMap<String, ForkAccount>,
    pub meta: ForkMeta,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkAccount {
    /// 运行时字节码 hex（无码 = "0x"）。
    pub code_hex: String,
    pub balance: String,
    pub nonce: String,
    /// 触及槽：slot hex（64 字符）→ value hex。
    pub slots: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkMeta {
    /// RPC URL（**不存 key**）。
    pub rpc_url: String,
    /// pin block（数字或 "latest" 解析后的 hex Tag）。
    pub block: String,
    pub fetched_at: u64,
    /// 内容摘要（keccak，完整性标识）。
    pub digest: String,
}

// ---------------------------------------------------------------------------
// 小 hex 工具（fuzz 自包含，不引 oracle——依赖方向 oracle → fuzz）
// ---------------------------------------------------------------------------

pub fn hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    if !hex.len().is_multiple_of(2) || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("非法字节 hex: {s:?}"));
    }
    Ok((0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("逐字符已验证"))
        .collect())
}

pub fn hex_u256(s: &str) -> Result<U256, String> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    if hex.is_empty() || hex.len() > 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("非法 U256 hex: {s:?}"));
    }
    U256::from_str_radix(hex, 16).map_err(|e| format!("非法 U256 hex {s:?}: {e}"))
}

pub fn u256_hex(v: U256) -> String {
    let mut s = String::with_capacity(66);
    s.push_str("0x");
    for b in v.to_be_bytes::<32>() {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

pub fn hex_addr(s: &str) -> Result<[u8; 20], String> {
    let b = hex_bytes(s)?;
    if b.len() != 20 {
        return Err(format!("非法地址 hex: {s:?}"));
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&b);
    Ok(a)
}

impl ForkStateFile {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("无法读取 state {}: {e}", path.display()))?;
        serde_json::from_str(&text).map_err(|e| format!("state JSON 解析失败: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        assert_eq!(hex_bytes("0xdead").unwrap(), vec![0xde, 0xad]);
        assert_eq!(
            hex_u256(&u256_hex(U256::from(0x42u64))).unwrap(),
            U256::from(0x42u64)
        );
        assert_eq!(
            hex_addr("0x000000000000000000000000000000000000c0de").unwrap()[19],
            0xde
        );
        assert!(hex_bytes("0xabc").is_err());
    }

    #[test]
    fn state_file_roundtrip() {
        let f = ForkStateFile {
            addresses: BTreeMap::from([(
                "0x00000000000000000000000000000000000000aa".to_string(),
                ForkAccount {
                    code_hex: "0x6000".to_string(),
                    balance: "0x1".to_string(),
                    nonce: "0x1".to_string(),
                    slots: BTreeMap::from([(
                        u256_hex(U256::from(2u64)),
                        u256_hex(U256::from(1u64)),
                    )]),
                },
            )]),
            meta: ForkMeta {
                rpc_url: "https://example".to_string(),
                block: "0x1".to_string(),
                fetched_at: 0,
                digest: "0x00".to_string(),
            },
        };
        let json = serde_json::to_vec(&f).unwrap();
        let back: ForkStateFile = serde_json::from_slice(&json).unwrap();
        assert_eq!(f, back);
    }
}
