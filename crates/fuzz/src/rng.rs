//! 确定性随机数：xorshift64*（V8 同款参数）。状态 8 字节，几十行，
//! 不引第三方依赖；全部随机性（变异、基线输入生成）经此产生，
//! `seed_rng` 相同则序列逐位相同。

/// xorshift64*：64 位状态，输出前做星式 scrambler（* 0x2545F4914F6CDD1D）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rng(u64);

impl Rng {
    /// 以 `seed` 初始化；`seed == 0` 替换为固定非零常量（xorshift
    /// 零状态恒输出零，无随机性）。
    pub fn new(seed: u64) -> Self {
        Rng(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    /// 下一个 64 位输出（同时推进状态）。
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// `[0, n)` 均匀整数。
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        // 拒绝采样避免取模偏差（n 远小于 2^64，偏差实践可忽略，
        // 但拒绝采样成本同样可忽略，顺手做对）。
        let zone = u64::MAX - (u64::MAX % n);
        loop {
            let v = self.next_u64();
            if v < zone {
                return v % n;
            }
        }
    }

    /// 填充随机字节。
    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        let mut chunks = out.chunks_mut(8);
        for chunk in &mut chunks {
            let word = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
    }

    /// 32 字节随机 word（大端，与 EVM 字布局一致）。
    pub fn word(&mut self) -> [u8; 32] {
        let mut w = [0u8; 32];
        self.fill_bytes(&mut w);
        w
    }

    /// 20 字节随机地址（大端）。
    pub fn address(&mut self) -> [u8; 20] {
        let mut a = [0u8; 20];
        self.fill_bytes(&mut a);
        a
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_sequence() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..64 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn zero_seed_not_degenerate() {
        let mut a = Rng::new(0);
        let mut b = Rng::new(0);
        let x = a.next_u64();
        assert_ne!(x, 0);
        assert_eq!(x, b.next_u64());
    }

    #[test]
    fn below_stays_in_range() {
        let mut rng = Rng::new(7);
        for _ in 0..10_000 {
            let v = rng.below(97);
            assert!(v < 97);
        }
    }
}
