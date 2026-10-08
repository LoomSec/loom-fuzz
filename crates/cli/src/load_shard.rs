//! 模式 B（纯文件）装载器：只有 `bytecode.hex` + `.lst` 两份文件，
//! shard 读取 + xlayer 展开 + 内置 arbitrary_call 检测，产出 `HitSet`。
//! 与模式 A 共用装配路径（`assemble`），保证两模式逐字段相等。

use std::path::Path;

use loom_fuzz_shard::Shard;
use loom_fuzz_xlayer::Xlayer;

use crate::detect::{detect_arbitrary_call, dominating_guards};
use crate::hitset::{Hit, HitSet, LoadError, SELECTOR_SENTINEL};
use crate::render::render_node;

/// 读取 bytecode.hex（运行时字节码的 hex 文本，允许 `0x` 前缀与首尾
/// 空白）。非法 hex → [`LoadError::CodeHexInvalid`]（fail-closed）。
pub(crate) fn read_code_hex(path: &Path) -> Result<Vec<u8>, LoadError> {
    let text = std::fs::read_to_string(path).map_err(|source| LoadError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let trimmed = text.trim();
    let hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if hex.is_empty() {
        return Ok(Vec::new());
    }
    if hex.len() % 2 != 0 {
        return Err(LoadError::CodeHexInvalid {
            path: path.to_path_buf(),
            reason: "奇数长度".to_string(),
        });
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        out.push(u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| {
            LoadError::CodeHexInvalid {
                path: path.to_path_buf(),
                reason: format!("非 hex 字符 at byte {}", i / 2),
            }
        })?);
    }
    Ok(out)
}

pub(crate) fn open_shard(path: &Path) -> Result<Shard, LoadError> {
    let bytes = std::fs::read(path).map_err(|source| LoadError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Shard::from_bytes(&bytes).map_err(LoadError::from)
}

/// 模式 B：`.lst` + `bytecode.hex` → `HitSet`。检测推导完全自包含。
pub fn load_from_shard(shard_path: &Path, code_hex: &Path) -> Result<HitSet, LoadError> {
    let code = read_code_hex(code_hex)?;
    let shard = open_shard(shard_path)?;
    let view = Xlayer::new(&shard);
    let raw = detect_arbitrary_call(&shard, &view);
    let rows = raw
        .iter()
        .map(|h| {
            let selector = shard.functions()[h.fn_idx]
                .selector
                .unwrap_or(SELECTOR_SENTINEL);
            Row {
                fn_idx: h.fn_idx,
                selector,
                step: h.step,
                evidence: render_node(&view, h.evidence),
                evidence_expr: Some(h.evidence),
                arm: Some(h.arm),
            }
        })
        .collect();
    assemble(&shard, &view, code, rows)
}

/// 装配期行：函数已解析为下标，证据已渲染为文本（两种模式在此汇合）。
/// 结构化表达式 id + 检测臂仅模式 B 有（模式 A 的 loom JSON 只给
/// 渲染文本，留 None——oracle 按形状启发 / fail-closed 兜底）。
pub(crate) struct Row {
    pub fn_idx: usize,
    pub selector: u32,
    pub step: u32,
    pub evidence: String,
    pub evidence_expr: Option<u32>,
    pub arm: Option<loom_fuzz_oracle::CallArm>,
}

/// 两种装载模式共享的装配：行（函数 + 步序 + 证据）→ 命中集。
/// step → pc 与支配 guard 都取本仓库 xlayer 展开流（与 loom 展开
/// 步序 golden 对拍一致，docs/architecture.md 模式 A 契约），装载来源
/// 无感。
pub(crate) fn assemble(
    shard: &Shard,
    view: &Xlayer<'_>,
    code: Vec<u8>,
    mut rows: Vec<Row>,
) -> Result<HitSet, LoadError> {
    rows.sort_by_key(|r| (r.selector, r.step));
    let mut hits = Vec::with_capacity(rows.len());
    for row in rows {
        let entries = view
            .expand(row.fn_idx)
            .expect("detect/装载行引用的函数必有展开流");
        let effect = entries.iter().find(|e| match e {
            loom_fuzz_xlayer::XEntry::Effect { step, .. } => *step == row.step,
            _ => false,
        });
        let Some(loom_fuzz_xlayer::XEntry::Effect { pc, scope, .. }) = effect else {
            return Err(LoadError::StepNotFound {
                selector: row.selector,
                step: row.step,
            });
        };
        let dominating = dominating_guards(shard, view, entries, row.step, *scope);
        hits.push(Hit {
            selector: row.selector,
            step: row.step,
            target_pcs: vec![*pc],
            evidence: row.evidence,
            evidence_expr: row.evidence_expr,
            arm: row.arm,
            dominating_guards: dominating,
        });
    }
    Ok(HitSet { code, hits })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_hex_parsing_accepts_prefix_and_whitespace() {
        let dir = std::env::temp_dir().join(format!("loom-fuzz-cli-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("code.hex");
        std::fs::write(&path, "  0x600a60  \n").unwrap();
        assert_eq!(read_code_hex(&path).unwrap(), vec![0x60, 0x0a, 0x60]);
    }

    #[test]
    fn code_hex_rejects_odd_and_non_hex() {
        let dir = std::env::temp_dir().join(format!("loom-fuzz-cli-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let odd = dir.join("odd.hex");
        std::fs::write(&odd, "0x123").unwrap();
        assert!(matches!(
            read_code_hex(&odd),
            Err(LoadError::CodeHexInvalid { .. })
        ));
        let bad = dir.join("bad.hex");
        std::fs::write(&bad, "zz").unwrap();
        assert!(matches!(
            read_code_hex(&bad),
            Err(LoadError::CodeHexInvalid { .. })
        ));
    }
}
