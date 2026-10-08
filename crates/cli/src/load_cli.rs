//! 模式 A（CLI 在位）装载器：子进程调用 loom-evm 发布的 `loom` 二进制，
//! `loom query <pack>... <shard> --json` 取 `vuln_arbitrary` 谓词的
//! rows；step → pc 与支配 guard 仍走本仓库 xlayer 展开（与模式 B 同源，
//! 见 docs/architecture.md 的模式 A 契约）。
//!
//! fail-closed：二进制缺失 / 非零退出 / JSON 缺字段 / 结果截断 /
//! 未满足 oracle demand / Func 列渲染无法识别，一律 typed 报错，
//! 不静默降级。

use std::path::Path;
use std::process::Command;

use loom_fuzz_shard::Shard;
use loom_fuzz_xlayer::Xlayer;

use crate::hitset::{HitSet, LoadError, SELECTOR_SENTINEL};
use crate::load_shard::{assemble, read_code_hex, Row};

const STDERR_LIMIT: usize = 4096;

/// 模式 A：`loom query <pack>... <shard> --json` + `bytecode.hex` →
/// `HitSet`。
///
/// `packs` 至少应含一个产出 `vuln_arbitrary` 谓词的检测 pack
/// （loom-evm 的 `packs/detect/arbitrary_call.lq` 即契约参考）。
pub fn load_from_cli(
    loom_bin: &Path,
    packs: &[&Path],
    shard: &Path,
    code_hex: &Path,
) -> Result<HitSet, LoadError> {
    if packs.is_empty() {
        return Err(LoadError::LoomJson {
            reason: "packs 为空：模式 A 至少需要一个检测 pack".to_string(),
        });
    }
    let code = read_code_hex(code_hex)?;
    let mut command = Command::new(loom_bin);
    command.arg("query");
    for pack in packs {
        command.arg(pack);
    }
    command.arg(shard).arg("--json");
    let output = command.output().map_err(|source| LoadError::LoomSpawn {
        path: loom_bin.to_path_buf(),
        source,
    })?;
    if !output.status.success() {
        let mut stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        stderr.truncate(STDERR_LIMIT);
        return Err(LoadError::LoomExit {
            status: output.status,
            stderr,
        });
    }
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|e| LoadError::LoomJson {
            reason: format!("stdout 不是合法 JSON: {e}"),
        })?;

    // oracle demand 未满足 = 结果可能不完整：fail-closed（issue #147 的
    // "must not read as a clean zero" 纪律）。
    let unserved = json
        .get("unserved_demand")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| LoadError::LoomJson {
            reason: "顶层缺 unserved_demand（uint）".to_string(),
        })?;
    if unserved > 0 {
        return Err(LoadError::LoomUnservedDemand {
            count: unserved as usize,
        });
    }

    let queries = json
        .get("queries")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| LoadError::LoomJson {
            reason: "顶层缺 queries 数组".to_string(),
        })?;
    let vuln = queries
        .iter()
        .find(|q| q.get("predicate").and_then(serde_json::Value::as_str) == Some("vuln_arbitrary"))
        .ok_or_else(|| LoadError::LoomJson {
            reason: "queries 中无 vuln_arbitrary 谓词结果段".to_string(),
        })?;
    let rows = vuln
        .get("rows")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| LoadError::LoomJson {
            reason: "vuln_arbitrary 缺 rows 数组".to_string(),
        })?;
    let total_rows = vuln
        .get("total_rows")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| LoadError::LoomJson {
            reason: "vuln_arbitrary 缺 total_rows（uint）".to_string(),
        })?;
    if rows.len() as u64 != total_rows {
        return Err(LoadError::LoomTruncated {
            predicate: "vuln_arbitrary".to_string(),
            total_rows: total_rows as usize,
            served_rows: rows.len(),
        });
    }
    // 顶层 truncated 旗标是同一事实的另一路声明，双保险。
    if json.get("truncated").and_then(serde_json::Value::as_bool) == Some(true) {
        return Err(LoadError::LoomTruncated {
            predicate: "vuln_arbitrary".to_string(),
            total_rows: total_rows as usize,
            served_rows: rows.len(),
        });
    }

    let mut parsed = Vec::with_capacity(rows.len());
    for row in rows {
        let cells = row.as_array().ok_or_else(|| LoadError::RowMalformed {
            predicate: "vuln_arbitrary".to_string(),
            reason: "行不是数组".to_string(),
        })?;
        if cells.len() != 3 {
            return Err(LoadError::RowMalformed {
                predicate: "vuln_arbitrary".to_string(),
                reason: format!("行列数 {} ≠ 3（期望 [func, step, t]）", cells.len()),
            });
        }
        let cell = |i: usize| -> Result<String, LoadError> {
            cells[i]
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| LoadError::RowMalformed {
                    predicate: "vuln_arbitrary".to_string(),
                    reason: format!("第 {i} 列不是字符串"),
                })
        };
        let func = cell(0)?;
        let step = cell(1)?;
        let evidence = cell(2)?;
        let step: u32 = step
            .parse()
            .map_err(|_| LoadError::StepMalformed { cell: step.clone() })?;
        parsed.push((parse_func(&func)?, step, evidence));
    }

    let shard_model = crate::load_shard::open_shard(shard)?;
    let view = Xlayer::new(&shard_model);
    let rows = parsed
        .into_iter()
        .map(|(f, step, evidence)| {
            let (fn_idx, selector) = resolve_func(&shard_model, f)?;
            Ok(Row {
                fn_idx,
                selector,
                step,
                evidence,
                evidence_expr: None,
                arm: None,
            })
        })
        .collect::<Result<Vec<_>, LoadError>>()?;
    assemble(&shard_model, &view, code, rows)
}

/// loom Func 列渲染的解析结果。
enum FuncRef {
    /// `0x%08x`：有 selector 的函数。
    Selector(u32),
    /// `f{local}@c{contract}`：无 selector 的函数（fallback/receive 等）。
    SelectorLess { local: usize, contract: usize },
}

fn parse_func(cell: &str) -> Result<FuncRef, LoadError> {
    let bad = || LoadError::FuncUnrecognized {
        cell: cell.to_string(),
    };
    if let Some(hex) = cell
        .strip_prefix("0x")
        .filter(|hex| hex.len() == 8 && hex.chars().all(|c| c.is_ascii_hexdigit()))
    {
        let selector = u32::from_str_radix(hex, 16).map_err(|_| bad())?;
        return Ok(FuncRef::Selector(selector));
    }
    if let Some(rest) = cell.strip_prefix('f') {
        if let Some((local, contract)) = rest.split_once("@c") {
            let local = local.parse::<usize>().map_err(|_| bad())?;
            let contract = contract.parse::<usize>().map_err(|_| bad())?;
            return Ok(FuncRef::SelectorLess { local, contract });
        }
    }
    Err(bad())
}

fn resolve_func(shard: &Shard, f: FuncRef) -> Result<(usize, u32), LoadError> {
    match f {
        FuncRef::Selector(selector) => {
            let idx = shard
                .functions()
                .iter()
                .position(|fun| fun.selector == Some(selector))
                .ok_or(LoadError::SelectorNotFound { selector })?;
            Ok((idx, selector))
        }
        FuncRef::SelectorLess { local, contract } => {
            // M0 单 shard 装载：contract 必须 0。
            if contract != 0 {
                return Err(LoadError::FuncUnrecognized {
                    cell: format!("f{local}@c{contract}（多 shard 装载未支持）"),
                });
            }
            if local >= shard.functions().len() {
                return Err(LoadError::FunctionIndexOutOfRange {
                    index: local,
                    functions: shard.functions().len(),
                });
            }
            let selector = shard.functions()[local]
                .selector
                .unwrap_or(SELECTOR_SENTINEL);
            Ok((local, selector))
        }
    }
}
