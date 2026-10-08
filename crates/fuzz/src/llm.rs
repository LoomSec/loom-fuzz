//! LLM 提案器（issue #25，feature `llm`）：OpenAI 兼容
//! `/v1/chat/completions`（env LLM_API_BASE/LLM_API_KEY/LLM_MODEL），
//! 把 per-hit 上下文（selector、目标 pc、支配 guard 渲染列表、最近
//! 反馈含失败 guard、值字典预览）组装 prompt，要求模型输出 JSON
//! 候选 calldata（selector + words 数组）。解析失败 / HTTP 错 →
//! 记 assumption 回退 DictionaryProposer（fail-closed 不静默）。
//! **prompt/响应全部落盘**（take_interactions → fuzz_report
//! llm_interactions 节）。**判决独立**：LLM 只影响搜索路径。

use std::sync::Mutex;
use std::time::{Duration, Instant};

use alloy_primitives::U256;
use loom_fuzz_seed::Input;

use crate::exec::{ProposalBudget, Proposer, ProposerCtx, RunFeedback};
use crate::propose::{words_to_input, DictionaryProposer};

pub use crate::propose::LlmInteraction;

/// 测试注入的 HTTP 传输形态。
type TransportFn = std::sync::Arc<dyn Fn(&str, &str, &str) -> Result<String, String> + Send + Sync>;

/// LLM 配置（env 读取；可显式传入便于测试）。
#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub api_base: String,
    pub api_key: String,
    pub model: String,
    /// 单次提案最多候选。
    pub max_candidates: usize,
    /// 冷却：两次 LLM 调用最小间隔（防限流；期间回退字典）。
    pub cooldown: Duration,
}

impl LlmConfig {
    /// 从 env 读取（LLM_API_BASE/LLM_API_KEY/LLM_API_MODEL）。
    pub fn from_env() -> Option<Self> {
        let key = std::env::var("LLM_API_KEY").ok().unwrap_or_default();
        if key.is_empty() {
            return None;
        }
        Some(LlmConfig {
            api_base: std::env::var("LLM_API_BASE")
                .unwrap_or_else(|_| "https://api.openai.com/v1".to_string()),
            api_key: key,
            model: std::env::var("LLM_API_MODEL").unwrap_or_else(|_| "gpt-4o-mini".to_string()),
            max_candidates: 6,
            cooldown: Duration::from_secs(5),
        })
    }
}

/// LLM 提案器：内嵌字典回退；冷却/停滞时直接走字典。
pub struct LlmProposer {
    dict_fallback: DictionaryProposer,
    cfg: LlmConfig,
    selector: u32,
    target_pcs: Vec<u32>,
    guards: Vec<(u32, String)>,
    dict_preview: Vec<U256>,
    interactions: Vec<LlmInteraction>,
    assumptions: Vec<String>,
    last_call: Option<Instant>,
    /// 连续无改进代数（停滞检测：>4 才再叫 LLM）。
    stall: u32,
    last_best: Option<u32>,
    /// 测试注入：HTTP 传输抽象（默认 ureq）。
    transport: Option<TransportFn>,
}

impl LlmProposer {
    pub fn new(
        cfg: LlmConfig,
        selector: u32,
        target_pcs: Vec<u32>,
        guards: Vec<(u32, String)>,
        dict_preview: Vec<U256>,
        dict_seed: u64,
    ) -> Self {
        LlmProposer {
            dict_fallback: DictionaryProposer::new(dict_seed),
            cfg,
            selector,
            target_pcs,
            guards,
            dict_preview,
            interactions: Vec::new(),
            assumptions: Vec::new(),
            last_call: None,
            stall: 0,
            last_best: None,
            transport: None,
        }
    }

    /// 测试注入：替换 HTTP 传输。
    #[cfg(test)]
    pub fn with_transport(mut self, t: TransportFn) -> Self {
        self.transport = Some(t);
        self
    }

    pub fn take_interactions(&mut self) -> Vec<LlmInteraction> {
        std::mem::take(&mut self.interactions)
    }

    pub fn take_assumptions(&mut self) -> Vec<String> {
        std::mem::take(&mut self.assumptions)
    }

    fn note_assumption(&mut self, text: String) {
        if !self.assumptions.contains(&text) {
            self.assumptions.push(text);
        }
    }

    /// 组 prompt：loom 特色上下文 = 目标 + 支配 guard + revert 归因
    /// + 求值偏差（距离）+ 字典预览。
    fn build_prompt(&self, feedback: &[RunFeedback]) -> String {
        let guards = if self.guards.is_empty() {
            "(none)".to_string()
        } else {
            self.guards
                .iter()
                .map(|(pc, cond)| format!("- pc{pc}: {cond}"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let recent = feedback
            .iter()
            .rev()
            .take(8)
            .map(|f| {
                let guard = f
                    .reverted_guard
                    .as_ref()
                    .map(|g| format!("guard@pc{} `{}`", g.pc, g.cond_rendered))
                    .unwrap_or_else(|| "no-guard".to_string());
                format!(
                    "- distance={} outcome={:?} head_words={} reverted_at={guard}",
                    f.best_distance,
                    f.outcome,
                    f.input.head.len()
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let dict = self
            .dict_preview
            .iter()
            .map(|w| format!("{w:#x}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "You are helping a directed fuzzer reach a target PC in an Ethereum contract.\n\
             Function selector: {selector:#010x}\n\
             Target PCs: {pcs:?}\n\
             Dominating guards (must pass):\n{guards}\n\
             Recent runs (distance = CFG distance to target; reverted_at = last dominating guard passed):\n{recent}\n\
             Value dictionary (candidates): {dict}\n\
             Task: propose up to {max} candidate calldata inputs as a JSON array. Each element: \
             {{\"selector\": \"0x{selector:08x}\", \"words\": [\"0x<64-hex>\", ...]}} \
             — words are the 32-byte head slots after the selector. \
             Favor the reverted_at guard's expected operands (from the dictionary). \
             Output ONLY the JSON array.",
            selector = self.selector,
            pcs = self.target_pcs,
            guards = guards,
            recent = recent,
            dict = dict,
            max = self.cfg.max_candidates,
        )
    }

    /// 解析模型输出：宽松扫描 JSON 数组——剥 markdown 围栏后，从
    /// 每个 '[' 位置尝试解析（reasoning 模型会在 JSON 前写长推理，
    /// 首个 '[' 不一定是数组起点）。
    fn parse_candidates(&self, text: &str) -> Result<Vec<Input>, String> {
        let cleaned = text.replace("```json", "").replace("```", "");
        let mut last_err = "响应无 JSON 数组".to_string();
        let starts: Vec<usize> = cleaned.match_indices('[').map(|(i, _)| i).take(8).collect();
        let mut arr: Option<serde_json::Value> = None;
        for start in starts {
            if let Some(end) = cleaned[start..].rfind(']') {
                let end = start + end;
                match serde_json::from_str::<serde_json::Value>(&cleaned[start..=end]) {
                    Ok(v) if v.is_array() => {
                        arr = Some(v);
                        break;
                    }
                    Ok(_) => last_err = "首个 JSON 值非数组".to_string(),
                    Err(e) => last_err = format!("JSON 解析失败: {e}"),
                }
            }
        }
        let arr = arr.ok_or(last_err)?;
        let arr = arr.as_array().ok_or("非数组")?;
        let mut out = Vec::new();
        for item in arr.iter().take(self.cfg.max_candidates) {
            let selector = item
                .get("selector")
                .and_then(|s| s.as_str())
                .and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                .unwrap_or(self.selector);
            let words = item
                .get("words")
                .and_then(|w| w.as_array())
                .map(|ws| {
                    ws.iter()
                        .filter_map(|x| x.as_str())
                        .filter_map(|s| U256::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if !words.is_empty() {
                out.push(words_to_input(selector, [0x33; 20], &words));
            }
        }
        if out.is_empty() {
            return Err("模型未给出可用候选".to_string());
        }
        Ok(out)
    }

    fn http_post(&self, url: &str, key: &str, body: &str) -> Result<String, String> {
        if let Some(t) = &self.transport {
            return t(url, key, body);
        }
        let agent = ureq::Agent::new_with_config(
            ureq::Agent::config_builder()
                .timeout_global(Some(Duration::from_secs(60)))
                .build(),
        );
        let req = agent
            .post(url)
            .header("Content-Type", "application/json")
            .header("Authorization", &format!("Bearer {key}"));
        let resp = req.send(body).map_err(|e| format!("HTTP 失败: {e}"))?;
        resp.into_body()
            .read_to_string()
            .map_err(|e| format!("读体失败: {e}"))
    }

    fn call_llm(&mut self, feedback: &[RunFeedback]) -> Vec<Input> {
        let prompt = self.build_prompt(feedback);
        let url = format!(
            "{}/chat/completions",
            self.cfg.api_base.trim_end_matches('/')
        );
        let body = serde_json::json!({
            "model": self.cfg.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "max_tokens": 8192,
        })
        .to_string();
        let result = self
            .http_post(&url, &self.cfg.api_key, &body)
            .and_then(|text| {
                let json: serde_json::Value =
                    serde_json::from_str(&text).map_err(|e| format!("响应非 JSON: {e}"))?;
                // deepseek 系 flash 模型常把答案放 reasoning_content、
                // content 为空——两者都试（content 优先）。
                let msg = &json["choices"][0]["message"];
                let content = msg["content"]
                    .as_str()
                    .filter(|s| !s.trim().is_empty())
                    .or_else(|| msg["reasoning_content"].as_str())
                    .ok_or("响应缺 choices[0].message.content/reasoning_content")?
                    .to_string();
                Ok((text, content))
            });
        match result {
            Ok((raw, content)) => {
                self.last_call = Some(Instant::now());
                match self.parse_candidates(&content) {
                    Ok(cands) => {
                        self.interactions.push(LlmInteraction {
                            prompt,
                            response: raw,
                            ok: true,
                            error: None,
                        });
                        cands
                    }
                    Err(e) => {
                        self.note_assumption(format!("LLM 候选解析失败，回退字典: {e}"));
                        self.interactions.push(LlmInteraction {
                            prompt,
                            response: raw,
                            ok: false,
                            error: Some(e),
                        });
                        Vec::new()
                    }
                }
            }
            Err(e) => {
                self.note_assumption(format!("LLM 调用失败，回退字典: {e}"));
                self.interactions.push(LlmInteraction {
                    prompt,
                    response: String::new(),
                    ok: false,
                    error: Some(e),
                });
                Vec::new()
            }
        }
    }
}

impl Proposer for LlmProposer {
    fn refresh(&mut self, ctx: &ProposerCtx<'_>) {
        self.dict_fallback.refresh(ctx);
    }

    fn drain_llm(&mut self) -> (Vec<crate::propose::LlmInteraction>, Vec<String>) {
        (self.take_interactions(), self.take_assumptions())
    }

    fn propose(&mut self, feedback: &[RunFeedback], budget: ProposalBudget) -> Vec<Input> {
        if budget.max_candidates == 0 || budget.time_left.is_zero() {
            return Vec::new();
        }
        // 停滞检测：距离无改进计数。
        let best = feedback.iter().map(|f| f.best_distance).min();
        match (best, self.last_best) {
            (Some(b), Some(l)) if b >= l => self.stall += 1,
            (Some(b), _) => {
                self.stall = 0;
                self.last_best = Some(b);
            }
            _ => {}
        }
        // 冷却满足且（首次或停滞 >4）才调 LLM；否则字典。
        let cooled = self
            .last_call
            .is_none_or(|t| t.elapsed() >= self.cfg.cooldown);
        let want_llm = self.last_call.is_none() || self.stall > 4;
        if cooled && want_llm {
            let cands = self.call_llm(feedback);
            if !cands.is_empty() {
                // LLM 候选优先 + 字典补位（不超预算）。
                let mut out = cands;
                let rest = budget.max_candidates.saturating_sub(out.len());
                if rest > 0 {
                    let fb = budget_slice(feedback, rest);
                    out.extend(self.dict_fallback.propose(
                        &fb,
                        ProposalBudget {
                            max_candidates: rest,
                            time_left: budget.time_left,
                        },
                    ));
                }
                return out;
            }
        }
        self.dict_fallback.propose(feedback, budget)
    }
}

fn budget_slice(feedback: &[RunFeedback], max: usize) -> Vec<RunFeedback> {
    feedback
        .iter()
        .rev()
        .take(max.max(1))
        .rev()
        .cloned()
        .collect()
}

/// 交互列表的线程安全提取助手（CLI 落 fuzz_report 用）。
pub type SharedInteractions = Mutex<Vec<LlmInteraction>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::{GuardFeedback, OutcomeKind};
    use loom_fuzz_seed::Tail;

    fn feedback() -> Vec<RunFeedback> {
        vec![RunFeedback {
            input: Input {
                selector: 0x2e2d2984,
                caller: [0x33; 20],
                value: U256::ZERO,
                head: vec![[0u8; 32]; 2],
                tail: Tail::Empty,
            },
            outcome: OutcomeKind::Revert,
            best_distance: 3,
            reverted_guard: Some(GuardFeedback {
                pc: 21,
                cond_rendered: "a == b".into(),
                polarity_failed: true,
            }),
        }]
    }

    fn budget() -> ProposalBudget {
        ProposalBudget {
            max_candidates: 8,
            time_left: Duration::from_secs(30),
        }
    }

    fn mk_proposer(transport: TransportFn) -> LlmProposer {
        LlmProposer::new(
            LlmConfig {
                api_base: "http://127.0.0.1:1/v1".into(),
                api_key: "test".into(),
                model: "m".into(),
                max_candidates: 4,
                cooldown: Duration::from_secs(0),
            },
            0x2e2d2984,
            vec![1327],
            vec![(21, "a == b".into())],
            vec![U256::from(0x42u64)],
            7,
        )
        .with_transport(transport)
    }

    use std::sync::Arc;

    #[test]
    fn llm_success_parses_candidates_and_logs() {
        let ok = Arc::new(|_u: &str, _k: &str, _b: &str| {
            Ok(serde_json::json!({
                "choices": [{"message": {"content": "[{\"selector\":\"0x2e2d2984\",\"words\":[\"0x0000000000000000000000000000000000000000000000000000000000000042\"]}]"}}]
            })
            .to_string())
        });
        let mut p = mk_proposer(ok);
        let cands = p.propose(&feedback(), budget());
        assert_eq!(cands.len(), 2); // 1 LLM + 1 字典补位
        assert_eq!(cands[0].selector, 0x2e2d2984);
        assert_eq!(U256::from_be_bytes(cands[0].head[0]), U256::from(0x42u64));
        let log = p.take_interactions();
        assert_eq!(log.len(), 1);
        assert!(log[0].ok);
        assert!(log[0].prompt.contains("pc21"));
        assert!(p.take_assumptions().is_empty());
    }

    #[test]
    fn llm_http_failure_falls_back_and_logs() {
        let bad = Arc::new(|_u: &str, _k: &str, _b: &str| Err("HTTP 500".to_string()));
        let mut p = mk_proposer(bad);
        let cands = p.propose(&feedback(), budget());
        // 回退字典：候选仍产出（字典路径），assumption 记录失败。
        assert!(!cands.is_empty());
        let log = p.take_interactions();
        assert_eq!(log.len(), 1);
        assert!(!log[0].ok);
        assert!(log[0].error.as_deref().unwrap().contains("500"));
        let notes = p.take_assumptions();
        assert!(notes.iter().any(|a| a.contains("LLM 调用失败")));
    }

    #[test]
    fn llm_bad_json_falls_back_and_logs() {
        let badjson = Arc::new(|_u: &str, _k: &str, _b: &str| Ok("not json at all".to_string()));
        let mut p = mk_proposer(badjson);
        let cands = p.propose(&feedback(), budget());
        assert!(!cands.is_empty(), "解析失败应回退字典");
        let log = p.take_interactions();
        assert!(!log[0].ok);
        assert!(p.take_assumptions().iter().any(|a| a.contains("回退字典")));
    }
}
