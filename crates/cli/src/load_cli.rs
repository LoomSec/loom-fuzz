//! 模式 A（CLI 在位）装载器：子进程调用 loom-evm 发布的 `loom` 二进制，
//! `loom query <pack>... <shard> --json` 取检测谓词（#20 多族：
//! arbitrary_call 的 `vuln_arbitrary` + approval_drain 的
//! `deputy_call`/`drain_forward`）的 rows；step → pc 与支配 guard
//! 仍走本仓库 xlayer 展开（与模式 B 同源，见 docs/architecture.md
//! 的模式 A 契约）。
//!
//! fail-closed：二进制缺失 / 非零退出 / JSON 缺字段 / 结果截断 /
//! 未满足 oracle demand / Func 列渲染无法识别，一律 typed 报错，
//! 不静默降级。三个谓词段全缺 = 契约外输入，报错。

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
/// `packs` 至少一个；产出段按已知谓词表解析（`vuln_arbitrary` /
/// `deputy_call` / `drain_forward`——loom-evm 的
/// `packs/detect/arbitrary_call.lq` 与 `packs/detect/approval_drain.lq`
/// 即契约参考）。三个谓词段全缺 = 契约外输入，fail-closed。
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

    /// 已知检测谓词：谓词名 → （族，列数）。deputy_call/drain_forward
    /// 来自 approval_drain pack（loom 的 gen_deputy_call 是中间谓词，
    /// 不装载——deputy_call 与其行集相同）。
    const PREDICATES: &[(&str, loom_fuzz_oracle::HitFamily, usize)] = &[
        (
            "vuln_arbitrary",
            loom_fuzz_oracle::HitFamily::ArbitraryCall,
            3,
        ),
        (
            "deputy_call",
            loom_fuzz_oracle::HitFamily::ApprovalDrainDeputy,
            3,
        ),
        (
            "drain_forward",
            loom_fuzz_oracle::HitFamily::ApprovalDrainForward,
            2,
        ),
    ];

    let mut parsed: Vec<(FuncRef, u32, String, loom_fuzz_oracle::HitFamily)> = Vec::new();
    let mut any_section = false;
    for (predicate, family, arity) in PREDICATES {
        let Some(section) = queries
            .iter()
            .find(|q| q.get("predicate").and_then(serde_json::Value::as_str) == Some(predicate))
        else {
            continue; // 该 pack 未参与查询：段缺失合法（族无行）
        };
        any_section = true;
        let rows = section
            .get("rows")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| LoadError::LoomJson {
                reason: format!("{predicate} 缺 rows 数组"),
            })?;
        let total_rows = section
            .get("total_rows")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| LoadError::LoomJson {
                reason: format!("{predicate} 缺 total_rows（uint）"),
            })?;
        if rows.len() as u64 != total_rows {
            return Err(LoadError::LoomTruncated {
                predicate: predicate.to_string(),
                total_rows: total_rows as usize,
                served_rows: rows.len(),
            });
        }
        for row in rows {
            let cells = row.as_array().ok_or_else(|| LoadError::RowMalformed {
                predicate: predicate.to_string(),
                reason: "行不是数组".to_string(),
            })?;
            if cells.len() != *arity {
                return Err(LoadError::RowMalformed {
                    predicate: predicate.to_string(),
                    reason: format!("行列数 {} ≠ {arity}", cells.len()),
                });
            }
            let cell = |i: usize| -> Result<String, LoadError> {
                cells[i]
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| LoadError::RowMalformed {
                        predicate: predicate.to_string(),
                        reason: format!("第 {i} 列不是字符串"),
                    })
            };
            let func = cell(0)?;
            let step = cell(1)?;
            // 证据列：deputy/vuln 有（渲染文本，仅报告对象）；drain 无
            //（loom 谓词本身不投影 t）——drain 行的证据渲染在装配期
            // 从 input operand 回填（classify_hit），此处留空串。
            let evidence = if *arity == 3 { cell(2)? } else { String::new() };
            let step: u32 = step
                .parse()
                .map_err(|_| LoadError::StepMalformed { cell: step.clone() })?;
            parsed.push((parse_func(&func)?, step, evidence, *family));
        }
    }
    // 顶层 truncated 旗标是同一事实的另一路声明，双保险。
    if json.get("truncated").and_then(serde_json::Value::as_bool) == Some(true) {
        return Err(LoadError::LoomTruncated {
            predicate: "（顶层 truncated 旗标）".to_string(),
            total_rows: 0,
            served_rows: 0,
        });
    }
    if !any_section {
        return Err(LoadError::LoomJson {
            reason: "queries 中无已知检测谓词段（vuln_arbitrary/deputy_call/drain_forward）"
                .to_string(),
        });
    }

    let shard_model = crate::load_shard::open_shard(shard)?;
    let view = Xlayer::new(&shard_model);
    let rows = parsed
        .into_iter()
        .map(|(f, step, evidence, family)| {
            let (fn_idx, selector) = resolve_func(&shard_model, f)?;
            // evidence_expr/arm 与模式 B 同源回填：loom query 只给渲染
            // 文本，结构化表达式 id 从本仓库展开流按步序定位，保证两
            // 模式 HitSet 逐字段相等（定位不到 = 步序语义分歧，报错）。
            // drain_forward 的证据文本也由此回填（input operand 渲染）。
            let (evidence_expr, arm) = crate::detect::classify_hit(&view, fn_idx, step, family)
                .ok_or_else(|| LoadError::StepMalformed {
                    cell: format!("fn {fn_idx} step {step} 无法在展开流定位 call 效果"),
                })?;
            let evidence = if evidence.is_empty() {
                crate::render::render_node(&view, evidence_expr)
            } else {
                evidence
            };
            Ok(Row {
                fn_idx,
                selector,
                step,
                family,
                evidence,
                evidence_expr: Some(evidence_expr),
                arm,
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
