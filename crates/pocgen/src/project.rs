//! forge 执行：生成工程后真跑 `forge test`——绿灯 = 终判；
//! 红灯 / forge 缺失 fail-closed（不假装成功）。

use std::io::ErrorKind;
use std::path::Path;
use std::process::Command;

use crate::synth::PocgenError;

/// 在工程目录跑 `forge test`，解析结果：退出码 0 = 绿灯（返回
/// forge 输出尾行供报告）；非 0 = 红灯，typed error 带全输出。
pub fn forge_test(project_dir: &Path) -> Result<String, PocgenError> {
    let output = Command::new("forge")
        .arg("test")
        .current_dir(project_dir)
        .output()
        .map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                PocgenError::ForgeUnavailable(e)
            } else {
                PocgenError::Io(e)
            }
        })?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    if !output.status.success() {
        return Err(PocgenError::ForgeFailed { output: combined });
    }
    // 绿灯：返回输出尾行（forge 的测试摘要，如
    // "[PASS] testExploit() (gas: 123456)" 与 "1 passed" 汇总）。
    let tail: Vec<&str> = combined.lines().filter(|l| !l.trim().is_empty()).collect();
    Ok(tail
        .iter()
        .rev()
        .take(6)
        .rev()
        .copied()
        .collect::<Vec<_>>()
        .join("\n"))
}
