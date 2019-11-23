use std::cmp::Ordering;
use std::mem;

use openssl::bn::{BigNum, BigNumContext, BigNumContextRef};
use openssl::error::ErrorStack;

use super::misc::expand;
use super::PRIME_SIZE;
use super::{EncodeBlock, EncodedShard};

/* e = 3 is fixed */
pub struct EncodingKey {
    ctx: BigNumContext,
    n: BigNum,
    d: BigNum,
}

// impl ordering
pub struct DecodingKey {
    ctx: BigNumContext,
    n: BigNum,
}

impl EncodeBlock {
    // rounds of encoding (trapdoor application)
    const ROUNDS: u32 = 2;

    // rounds of feistel cipher / full-domain hashing
    const FEISTEL: u32 = 8;

    // feistel based permutation
    #[inline(always)]
    fn feistel(
        &mut self,
        ctx: &mut BigNumContextRef,
        reverse: bool,
        n: &BigNum, // modulus
    ) -> Result<(), ErrorStack> {
        // F function
        fn f(
            ctx: &mut BigNumContextRef,
            res: &mut BigNum,
            tweak: &[u8],
            v: &BigNum,
            n: &BigNum,
        ) -> Result<(), ErrorStack> {
            // stretch into a large random string
            let len = (n.num_bytes() + 16) as usize;
            let random = expand(tweak, &v.to_vec(), len);

            // reduce mod n
            let random = BigNum::from_slice(&random[..])?;
            res.nnmod(&random, n, ctx)
        }

        let mut tmp1 = BigNum::new()?;
        let mut tmp2 = BigNum::new()?;
        let mut tweak = [0u8; 1];

        debug_assert_eq!(self.s[0].ucmp(n), Ordering::Less);
        debug_assert_eq!(self.s[1].ucmp(n), Ordering::Less);

        for r in 0..Self::FEISTEL {
            tweak[0] = if reverse { Self::FEISTEL - 1 - r } else { r } as u8;

            // P = F(b[0])
            f(ctx, &mut tmp1, &tweak[..], &self.s[0], &n)?;

            // mix with right half
            let mut new = BigNum::new()?;
            if reverse {
                // b[1] *= P
                new.mod_mul(&&self.s[1], &tmp1, &n, ctx)?;
            } else {
                // b[1] *= P^-1
                tmp2.mod_inverse(&tmp1, &n, ctx)?;
                new.mod_mul(&&self.s[1], &tmp2, &n, ctx)?;
            }

            // swap
            if r < Self::FEISTEL - 1 {
                // swap(b[0], b[1])
                mem::swap(&mut self.s[0], &mut new);
                mem::swap(&mut self.s[1], &mut new);
            } else {
                // dont swap at last round
                mem::swap(&mut self.s[1], &mut new);
            }
        }
        Ok(())
    }

    // 1 round of decoding
    fn round_inv(
        &mut self,
        ctx: &mut BigNumContextRef,
        n: &BigNum, // modulus
    ) -> Result<(), ErrorStack> {
        // apply RSA permutation

        for i in 0..2 {
            let old = self.s[i].to_owned()?;
            rsa_p(ctx, &mut self.s[i], &old, n)?;
        }

        // apply feistel

        self.feistel(ctx, true, n)?;

        Ok(())
    }

    // 1 round of encoding
    fn round(
        &mut self,
        ctx: &mut BigNumContextRef,
        n: &BigNum, // modulus
        t: &BigNum, // trapdoor
    ) -> Result<(), ErrorStack> {
        // apply feistel

        self.feistel(ctx, false, n)?;

        // apply trapdoor

        for i in 0..2 {
            let old = self.s[i].to_owned()?;
            rsa_pinv(ctx, &mut self.s[i], &old, n, t)?;
        }

        Ok(())
    }

    pub fn encode(
        &mut self,
        ctx: &mut BigNumContextRef,
        n: &BigNum,
        t: &BigNum,
    ) -> Result<(), ErrorStack> {
        for _r in 0..Self::ROUNDS {
            self.round(ctx, n, t)?;
        }
        Ok(())
    }

    pub fn decode(&mut self, ctx: &mut BigNumContextRef, n: &BigNum) -> Result<(), ErrorStack> {
        for _r in 0..Self::ROUNDS {
            self.round_inv(ctx, n)?;
        }
        Ok(())
    }
}

pub fn rsa_p(
    ctx: &mut BigNumContextRef,
    res: &mut BigNum,
    v: &BigNum,
    n: &BigNum,
) -> Result<(), ErrorStack> {
    let mut tmp = BigNum::new()?;
    tmp.mod_sqr(v, n, ctx)?;
    res.mod_mul(&tmp, v, n, ctx)
}

pub fn rsa_pinv(
    ctx: &mut BigNumContextRef,
    res: &mut BigNum,
    v: &BigNum,
    n: &BigNum,
    t: &BigNum,
) -> Result<(), ErrorStack> {
    res.mod_exp(v, t, n, ctx)
}

fn generate(ctx: &mut BigNumContextRef, n: &mut BigNum, d: &mut BigNum) -> Result<(), ErrorStack> {
    let e = BigNum::from_u32(3)?;
    let mut tmp = BigNum::new()?;
    let mut p = BigNum::new()?;
    let mut q = BigNum::new()?;

    p.generate_prime(PRIME_SIZE as i32, false, None, None)?;
    q.generate_prime(PRIME_SIZE as i32, false, None, None)?;
    n.checked_mul(&p, &q, ctx)?;

    p.sub_word(1)?;
    q.sub_word(1)?;

    tmp.checked_mul(&p, &q, ctx)?;
    d.mod_inverse(&e, &tmp, ctx)
}

impl EncodingKey {
    pub fn new() -> Self {
        let mut ctx = BigNumContext::new().unwrap();
        let mut n = BigNum::new().unwrap();
        let mut d = BigNum::new().unwrap();
        generate(&mut ctx, &mut n, &mut d).unwrap();
        EncodingKey { ctx, n, d }
    }

    pub fn encode(&mut self, s: &mut EncodedShard) {
        for block in s.blocks.iter_mut() {
            block.encode(&mut self.ctx, &self.n, &self.d).unwrap();
        }
    }

    pub fn decoding(&self) -> DecodingKey {
        DecodingKey {
            ctx: BigNumContext::new().unwrap(),
            n: self.n.to_owned().unwrap(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let n = self.n.to_vec();
        let d = self.d.to_vec();
        let mut ser = Vec::with_capacity(n.len() + d.len() + 2);
        ser.extend(&(n.len() as u16).to_be_bytes());
        ser.extend(n);
        ser.extend(d);
        ser
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() < 2 {
            return Err(());
        }

        // load length of n
        let mut l: [u8; 2] = [0u8; 2];
        l.copy_from_slice(&bytes[..2]);
        let l: usize = u16::from_be_bytes(l) as usize;
        if l >= bytes.len() - 2 {
            return Err(());
        }

        // split into n and d
        let ctx = BigNumContext::new().unwrap();
        let n = BigNum::from_slice(&bytes[2..2 + l]).map_err(|_| ())?;
        let d = BigNum::from_slice(&bytes[2 + l..]).map_err(|_| ())?;
        Ok(EncodingKey { ctx, d, n })
    }
}

impl DecodingKey {
    pub fn decode(&mut self, s: &mut EncodedShard) {
        for block in s.blocks.iter_mut() {
            block.decode(&mut self.ctx, &self.n).unwrap();
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.n.to_vec()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, ()> {
        let ctx = BigNumContext::new().unwrap();
        let n = BigNum::from_slice(bytes).map_err(|_| ())?;
        Ok(DecodingKey { ctx, n })
    }
}
