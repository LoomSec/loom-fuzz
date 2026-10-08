//! 256 位 EVM 字（`Word`）及其具体运算语义。
//!
//! 语义照抄 loom-evm `word.rs` 的 `apply_unary_op` / `apply_binary_op`
//! 运算表（代入折叠 `fold_operator` 的唯一裁判，见 `fold` 模块）：
//! 字节序为大端 32 字节数组，比较即无符号数值序；`/`、`%` 除零得 0；
//! `sdiv`/`smod` 为二进制补码语义；`*` 为模 2^256 乘方（平方乘，
//! 指数按位扫描）；`byte` 下标越界得 0；移位量 ≥256 得 0（算术右移
//! 负数则得全 1）。不认识的算子一律返回 `None`（不折叠）。

use std::cmp::Ordering;

/// EVM 256 位字：大端 32 字节（与 loom-evm `Word` 同构）。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Word(pub [u8; 32]);

impl Word {
    pub const ZERO: Word = Word([0u8; 32]);

    pub fn from_u64(value: u64) -> Word {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Word(bytes)
    }

    /// 仅当高 28 字节为零时给出低 32 位值。
    pub fn as_u32(self) -> Option<u32> {
        if self.0[..28].iter().any(|byte| *byte != 0) {
            return None;
        }
        Some(u32::from_be_bytes(self.0[28..].try_into().unwrap()))
    }

    /// 仅当高 24 字节为零时给出低 64 位值。
    pub fn as_u64(self) -> Option<u64> {
        if self.0[..24].iter().any(|byte| *byte != 0) {
            return None;
        }
        Some(u64::from_be_bytes(self.0[24..].try_into().unwrap()))
    }

    pub fn is_zero(self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }

    pub fn is_negative(self) -> bool {
        self.0[0] & 0x80 != 0
    }

    /// 无符号比较（大端字节序的字典序即数值序）。
    pub fn cmp_u(self, other: Word) -> Ordering {
        self.0.cmp(&other.0)
    }

    pub fn max(self, other: Word) -> Word {
        if self.cmp_u(other) == Ordering::Less {
            other
        } else {
            self
        }
    }

    pub fn min(self, other: Word) -> Word {
        if self.cmp_u(other) == Ordering::Greater {
            other
        } else {
            self
        }
    }

    pub fn wrapping_add(self, other: Word) -> Word {
        let mut out = [0u8; 32];
        let mut carry = 0u16;
        for index in (0..32).rev() {
            let sum = u16::from(self.0[index]) + u16::from(other.0[index]) + carry;
            out[index] = sum as u8;
            carry = sum >> 8;
        }
        Word(out)
    }

    pub fn wrapping_sub(self, other: Word) -> Word {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for index in (0..32).rev() {
            let diff = i16::from(self.0[index]) - i16::from(other.0[index]) - borrow;
            if diff < 0 {
                out[index] = (diff + 256) as u8;
                borrow = 1;
            } else {
                out[index] = diff as u8;
                borrow = 0;
            }
        }
        Word(out)
    }

    pub fn wrapping_neg(self) -> Word {
        Word::ZERO.wrapping_sub(self)
    }

    pub fn wrapping_mul(self, other: Word) -> Word {
        let mut limbs = [0u32; 64];
        for left in 0..32 {
            for right in 0..32 {
                limbs[left + right + 1] += u32::from(self.0[left]) * u32::from(other.0[right]);
            }
        }
        for index in (1..64).rev() {
            let carry = limbs[index] >> 8;
            limbs[index] &= 0xff;
            limbs[index - 1] += carry;
        }
        let mut out = [0u8; 32];
        for (destination, value) in out.iter_mut().zip(&limbs[32..]) {
            *destination = *value as u8;
        }
        Word(out)
    }

    pub fn wrapping_pow(self, exponent: Word) -> Word {
        let mut result = Word::from_u64(1);
        let mut base = self;
        for bit in 0..256 {
            if exponent.bit_le(bit) {
                result = result.wrapping_mul(base);
            }
            base = base.wrapping_mul(base);
        }
        result
    }

    pub fn bit_not(self) -> Word {
        let mut out = self.0;
        for byte in &mut out {
            *byte = !*byte;
        }
        Word(out)
    }

    pub fn bit_or(self, other: Word) -> Word {
        let mut out = [0u8; 32];
        for index in 0..32 {
            out[index] = self.0[index] | other.0[index];
        }
        Word(out)
    }

    pub fn bit_xor(self, other: Word) -> Word {
        let mut out = [0u8; 32];
        for index in 0..32 {
            out[index] = self.0[index] ^ other.0[index];
        }
        Word(out)
    }

    pub fn bit_and(self, other: Word) -> Word {
        let mut out = [0u8; 32];
        for index in 0..32 {
            out[index] = self.0[index] & other.0[index];
        }
        Word(out)
    }

    pub fn shift_left(self, amount: u32) -> Word {
        if amount >= 256 {
            return Word::ZERO;
        }
        let mut out = [0u8; 32];
        let bytes = (amount / 8) as usize;
        let bits = amount % 8;
        for (source, &byte) in self.0.iter().enumerate() {
            if source < bytes {
                continue;
            }
            let destination = source - bytes;
            out[destination] |= byte << bits;
            if bits != 0 && destination > 0 {
                out[destination - 1] |= byte >> (8 - bits);
            }
        }
        Word(out)
    }

    pub fn shift_right(self, amount: u32) -> Word {
        if amount >= 256 {
            return Word::ZERO;
        }
        let mut out = [0u8; 32];
        let bytes = (amount / 8) as usize;
        let bits = amount % 8;
        for (source, &byte) in self.0.iter().enumerate() {
            let destination = source + bytes;
            if destination >= 32 {
                continue;
            }
            out[destination] |= byte >> bits;
            if bits != 0 && destination + 1 < 32 {
                out[destination + 1] |= byte << (8 - bits);
            }
        }
        Word(out)
    }

    pub fn arithmetic_shift_right(self, amount: u32) -> Word {
        if !self.is_negative() {
            return self.shift_right(amount);
        }
        if amount >= 256 {
            return Word([0xff; 32]);
        }
        let mut out = self.shift_right(amount).0;
        let whole_bytes = (amount / 8) as usize;
        let remaining_bits = amount % 8;
        out[..whole_bytes].fill(0xff);
        if remaining_bits != 0 {
            out[whole_bytes] |= 0xff << (8 - remaining_bits);
        }
        Word(out)
    }

    pub fn unsigned_div(self, divisor: Word) -> Word {
        self.unsigned_div_rem(divisor)
            .map_or(Word::ZERO, |(quotient, _)| quotient)
    }

    pub fn unsigned_mod(self, divisor: Word) -> Word {
        self.unsigned_div_rem(divisor)
            .map_or(Word::ZERO, |(_, remainder)| remainder)
    }

    pub fn signed_div(self, divisor: Word) -> Word {
        if divisor.is_zero() {
            return Word::ZERO;
        }
        let negative = self.is_negative() ^ divisor.is_negative();
        let dividend = if self.is_negative() {
            self.wrapping_neg()
        } else {
            self
        };
        let divisor = if divisor.is_negative() {
            divisor.wrapping_neg()
        } else {
            divisor
        };
        let quotient = dividend.unsigned_div(divisor);
        if negative {
            quotient.wrapping_neg()
        } else {
            quotient
        }
    }

    pub fn signed_mod(self, divisor: Word) -> Word {
        if divisor.is_zero() {
            return Word::ZERO;
        }
        let negative = self.is_negative();
        let dividend = if negative { self.wrapping_neg() } else { self };
        let divisor = if divisor.is_negative() {
            divisor.wrapping_neg()
        } else {
            divisor
        };
        let remainder = dividend.unsigned_mod(divisor);
        if negative && !remainder.is_zero() {
            remainder.wrapping_neg()
        } else {
            remainder
        }
    }

    /// EVM `SIGNEXTEND`：`byte_index` 越界或 ≥32 时原样返回。
    pub fn sign_extend(self, byte_index: Word) -> Word {
        let Some(byte_index) = byte_index.as_u64() else {
            return self;
        };
        if byte_index >= 32 {
            return self;
        }
        let sign_byte = 31 - byte_index as usize;
        let fill = if self.0[sign_byte] & 0x80 == 0 {
            0x00
        } else {
            0xff
        };
        let mut out = self.0;
        out[..sign_byte].fill(fill);
        Word(out)
    }

    pub fn unsigned_div_rem(self, divisor: Word) -> Option<(Word, Word)> {
        if divisor.is_zero() {
            return None;
        }
        let mut quotient = Word::ZERO;
        let mut remainder = Word::ZERO;
        for bit in (0..256).rev() {
            let carried = remainder.0[0] & 0x80 != 0;
            remainder = remainder.shift_left(1);
            if self.bit_le(bit) {
                remainder.0[31] |= 1;
            }
            if carried || remainder.cmp_u(divisor) != Ordering::Less {
                remainder = remainder.wrapping_sub(divisor);
                quotient.set_bit_le(bit);
            }
        }
        Some((quotient, remainder))
    }

    fn bit_le(self, index: usize) -> bool {
        let byte = 31 - index / 8;
        self.0[byte] & (1 << (index % 8)) != 0
    }

    fn set_bit_le(&mut self, index: usize) {
        let byte = 31 - index / 8;
        self.0[byte] |= 1 << (index % 8);
    }
}

/// 二元算子的具体语义（loom-evm `apply_binary_op` 运算表照抄）。
/// 操作数顺序为 facts 顺序：除移位外都是 EVM 顺序，移位读作
/// `value << amount` / `value >> amount` / `value sar amount`。
pub fn apply_binary_op(op: &str, a: Word, b: Word) -> Option<Word> {
    let boolean = |value: bool| Word::from_u64(u64::from(value));
    let amount = |value: Word| value.as_u32().unwrap_or(256);
    Some(match op {
        "+" => a.wrapping_add(b),
        "-" => a.wrapping_sub(b),
        "*" => a.wrapping_mul(b),
        "/" => a.unsigned_div(b),
        "%" => a.unsigned_mod(b),
        "sdiv" => a.signed_div(b),
        "smod" => a.signed_mod(b),
        "**" => a.wrapping_pow(b),
        "signextend" => b.sign_extend(a),
        "byte" => match a.as_u64() {
            Some(index) if index < 32 => Word::from_u64(u64::from(b.0[index as usize])),
            _ => Word::ZERO,
        },
        "&" => a.bit_and(b),
        "|" => a.bit_or(b),
        "^" => a.bit_xor(b),
        "~" => a.bit_not(),
        "is-zero" => boolean(a.is_zero()),
        "<<" => a.shift_left(amount(b)),
        ">>" => a.shift_right(amount(b)),
        "sar" => a.arithmetic_shift_right(amount(b)),
        "max" => a.max(b),
        "min" => a.min(b),
        "ceil-div" => {
            if b.is_zero() {
                return None;
            }
            let quotient = a.unsigned_div(b);
            if a.unsigned_mod(b).is_zero() {
                quotient
            } else {
                quotient.wrapping_add(Word::from_u64(1))
            }
        }
        "align-up" | "align-down" => {
            if b.is_zero() {
                return None;
            }
            let down = a.unsigned_div(b).wrapping_mul(b);
            if op == "align-down" || down == a {
                down
            } else {
                down.wrapping_add(b)
            }
        }
        _ => return None,
    })
}

/// 一元算子的具体语义（loom-evm `apply_unary_op` 运算表照抄）。
pub fn apply_unary_op(op: &str, a: Word) -> Option<Word> {
    let boolean = |value: bool| Word::from_u64(u64::from(value));
    Some(match op {
        "~" => a.bit_not(),
        "is-zero" | "not" => boolean(a.is_zero()),
        "nonzero" => boolean(!a.is_zero()),
        "lowbit" => a.bit_and(a.wrapping_neg()),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(value: u64) -> Word {
        Word::from_u64(value)
    }

    /// 首字节为 `head`、其余全 `fill` 的字（构造断言期望用）。
    fn headed(head: u8, fill: u8) -> Word {
        let mut bytes = [fill; 32];
        bytes[0] = head;
        Word(bytes)
    }

    #[test]
    fn arithmetic_mod_2_pow_256() {
        let max = Word([0xff; 32]);
        assert_eq!(max.wrapping_add(word(1)), Word::ZERO);
        assert_eq!(word(0).wrapping_sub(word(1)), max);
        assert_eq!(word(3).wrapping_mul(word(7)), word(21));
    }

    #[test]
    fn div_rem_and_signed_variants() {
        let max = Word([0xff; 32]);
        let two = word(2);
        assert_eq!(max.unsigned_div(two), headed(0x7f, 0xff));
        assert_eq!(max.unsigned_mod(two), word(1));
        // max 作为有符号数是 -1：sdiv 2 = 0（向零截断），smod 2 = -1。
        assert_eq!(max.signed_div(two), Word::ZERO);
        assert_eq!(max.signed_mod(two), Word([0xff; 32]));
        // 除零：无符号得 0，signed_div 得 0。
        assert_eq!(word(9).unsigned_div(Word::ZERO), Word::ZERO);
        assert_eq!(word(9).signed_div(Word::ZERO), Word::ZERO);
    }

    #[test]
    fn shifts_and_byte_semantics() {
        assert_eq!(word(1).shift_left(255), headed(0x80, 0));
        assert_eq!(word(1).shift_left(256), Word::ZERO);
        assert_eq!(headed(0x80, 0).shift_right(255), word(1));
        // byte 按大端字节序取：byte(30, 0xdead) = 0xde，byte(31) = 0xad，
        // 越界得 0。
        assert_eq!(
            apply_binary_op("byte", word(30), word(0xdead)),
            Some(word(0xde))
        );
        assert_eq!(
            apply_binary_op("byte", word(31), word(0xdead)),
            Some(word(0xad))
        );
        assert_eq!(
            apply_binary_op("byte", word(32), word(0xdead)),
            Some(Word::ZERO)
        );
    }

    #[test]
    fn pow_and_signextend() {
        assert_eq!(word(2).wrapping_pow(word(10)), word(1024));
        // signextend(0, 0xff) = -1（全 1）。
        assert_eq!(
            apply_binary_op("signextend", word(0), word(0xff)),
            Some(Word([0xff; 32]))
        );
    }

    #[test]
    fn unknown_ops_do_not_fold() {
        assert_eq!(apply_binary_op("storage", word(1), word(2)), None);
        assert_eq!(apply_unary_op("keccak", word(1)), None);
    }
}
