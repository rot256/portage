#![feature(test)]

use std::mem;
use std::cmp::Ordering;

use openssl::bn::{BigNum, BigNumContextRef, BigNumContext, MsbOption};
use openssl::sha::Sha256;
use openssl::error::ErrorStack;
use openssl::symm::{encrypt, Cipher};

extern crate test;

// group size
const PRIME_SIZE: usize = 1025;
const MODULUS_SIZE: usize = 2 * PRIME_SIZE;

// message always slightly smaller to ensure that it is contained
const HALF_SIZE: usize = 2048;
const HALF_SIZE_BYTES: usize = HALF_SIZE / 8;
const MESSAGE_SIZE: usize = 2 * HALF_SIZE;
const MESSAGE_SIZE_BYTES: usize = 2 * HALF_SIZE_BYTES;

const FDH_ROUNDS: usize = 3;

fn rsa_p(
    ctx: &mut BigNumContextRef,
    res: &mut BigNum,
    v: &BigNum,
    n: &BigNum
) -> Result<(), ErrorStack> {
    let mut tmp = BigNum::new()?;
    tmp.mod_sqr(v, n, ctx)?;
    res.mod_mul(&tmp, v, n, ctx)
}

fn rsa_pinv(
    ctx: &mut BigNumContextRef,
    res: &mut BigNum,
    v: &BigNum,
    n: &BigNum,
    t: &BigNum
) -> Result<(), ErrorStack> {
    res.mod_exp(v, t, n, ctx)
}

fn generate(
    ctx: &mut BigNumContextRef,
    n: &mut BigNum,
    t: &mut BigNum
) -> Result<(), ErrorStack> {

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
    t.mod_inverse(&e, &tmp, ctx)
}

fn fdh(data : Vec<u8>, rounds: usize, reverse: bool) -> Vec<u8> {
    // split into left/right
    let mut left = data;
    let mut right = left.split_off(left.len() / 2);

    // apply feistel
    for r in 0..rounds {
        let tweak: [u8; 1] = [if reverse { rounds - r - 1 } else { r } as u8];
        let pad = expand(&tweak, &left[..], right.len());
        for i in 0..right.len() {
            right[i] ^= pad[i];
        }

        if r < rounds - 1 {
            mem::swap(&mut left, &mut right);
        }
    }

    // join again
    left.extend(right);
    left
}

fn split(data: &[u8]) -> Vec<State> {

    // pad and extend to multiple of chunk size

    let mut data = data.to_owned();
    data.push(0x1);
    while data.len() % MESSAGE_SIZE_BYTES != 0 {
        data.push(0x0);
    }
    assert_eq!(data.len() % MESSAGE_SIZE_BYTES, 0);

    // full-domain hashing

    let data = fdh(data, FDH_ROUNDS, false);
    assert_eq!(data.len() % MESSAGE_SIZE_BYTES, 0);

    // split into 512 byte chunks

    let num_chunks = data.len() / MESSAGE_SIZE_BYTES;
    let mut chunks = Vec::with_capacity(num_chunks);
    for c in 0..num_chunks {
        let l = c*MESSAGE_SIZE_BYTES;
        let m = l + HALF_SIZE_BYTES;
        let r = m + HALF_SIZE_BYTES;
        let s0 = BigNum::from_slice(&data[l..m]).unwrap();
        let s1 = BigNum::from_slice(&data[m..r]).unwrap();
        chunks.push(State{s: [s0, s1]})
    }

    chunks
}

fn join(states: &[State]) -> Vec<u8> {

    // join all states

    let mut data = Vec::with_capacity(
        states.len() * MESSAGE_SIZE_BYTES
    );

    for st in states {
        data.extend(st.s[0].to_vec());
        data.extend(st.s[1].to_vec());
    }

    // apply full domain hashing

    let mut data = fdh(data, FDH_ROUNDS, true);

    // remove padding

    while let Some(0) = data.pop() {};

    data
}

fn expand(
    tweak: &[u8],
    value: &[u8],
    size: usize
) -> Vec<u8> {
    // hash the input
    let mut hsh = Sha256::new();
    hsh.update(tweak);
    hsh.update(value);
    let key = hsh.finish();

    // allocate result buffer
    let mut zero : Vec<u8> = Vec::with_capacity(size);
    zero.resize(size, 0);

    // stretch into a large random number using AES-CTR
    let iv = [0u8; 16];
    let cipher = Cipher::aes_256_ctr();
    encrypt(
        cipher,
        &key[..],
        Some(&iv[..]),
        &zero[..]
    ).unwrap()
}

#[derive(Debug)]
struct State {
    s: [BigNum; 2]
}

impl State {

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
        n : &BigNum, // modulus
    ) -> Result<(), ErrorStack> {

        // F function
        fn f(
            ctx: &mut BigNumContextRef,
            res: &mut BigNum,
            tweak: &[u8],
            v: &BigNum,
            n: &BigNum
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
            tweak[0] = if reverse {
                Self::FEISTEL - 1 - r
            } else {
                r
            } as u8;

            // P = F(b[0])
            f(
                ctx,
                &mut tmp1,
                &tweak[..],
                &self.s[0],
                &n
            )?;

            // mix with right half
            let mut new = BigNum::new()?;
            if reverse {
                // b[1] *= P
                new.mod_mul(&
                    &self.s[1],
                    &tmp1,
                    &n,
                    ctx
                )?;
            } else {
                // b[1] *= P^-1
                tmp2.mod_inverse(&tmp1, &n, ctx)?;
                new.mod_mul(&
                    &self.s[1],
                    &tmp2,
                    &n,
                    ctx
                )?;
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
        n: &BigNum // modulus
    ) -> Result<(), ErrorStack> {

        // apply RSA permutation

        for i in 0..2 {
            let old = self.s[i].to_owned()?;
            rsa_p(
                ctx,
                &mut self.s[i],
                &old,
                n
            )?;
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
        t: &BigNum  // trapdoor
    ) -> Result<(), ErrorStack> {
        // apply feistel

        self.feistel(ctx, false, n)?;

        // apply trapdoor

        for i in 0..2 {
            let old = self.s[i].to_owned()?;
            rsa_pinv(
                ctx,
                &mut self.s[i],
                &old,
                n,
                t
            )?;
        }


        Ok(())
    }

    pub fn encode(
        &mut self,
        ctx: &mut BigNumContextRef,
        n: &BigNum,
        t: &BigNum
    ) -> Result<(), ErrorStack> {
        for _r in 0..Self::ROUNDS {
            self.round(ctx, n, t)?;
        }
        Ok(())
    }

    pub fn decode(
        &mut self,
        ctx: &mut BigNumContextRef,
        n: &BigNum
    ) -> Result<(), ErrorStack> {
        for _r in 0..Self::ROUNDS {
            self.round_inv(ctx, n)?;
        }
        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use test::Bencher;

    #[bench]
    fn bench_encode(b: &mut Bencher) {
        let mut ctx = BigNumContext::new().unwrap();
        let mut n = BigNum::new().unwrap();
        let mut t = BigNum::new().unwrap();

        generate(&mut ctx, &mut n, &mut t).unwrap();

        let mut s0 = BigNum::new().unwrap();
        let mut s1 = BigNum::new().unwrap();

        s0.rand(HALF_SIZE as i32, MsbOption::ONE, false).unwrap();
        s1.rand(HALF_SIZE as i32, MsbOption::ONE, false).unwrap();

        let mut st = State{s: [s0, s1]};

        // time to encode 1 KB
        b.iter(|| {
            let bytes = 1024;
            for _ in 0..(bytes / MESSAGE_SIZE_BYTES) {
                st.encode(&mut ctx, &n, &t).unwrap();
            }
        });
    }

    #[bench]
    fn bench_decode(b: &mut Bencher) {
        let mut ctx = BigNumContext::new().unwrap();
        let mut n = BigNum::new().unwrap();
        let mut t = BigNum::new().unwrap();

        generate(&mut ctx, &mut n, &mut t).unwrap();

        let mut s0 = BigNum::new().unwrap();
        let mut s1 = BigNum::new().unwrap();

        s0.rand(HALF_SIZE as i32, MsbOption::ONE, false).unwrap();
        s1.rand(HALF_SIZE as i32, MsbOption::ONE, false).unwrap();

        let mut st = State{s: [s0, s1]};

        st.encode(&mut ctx, &n, &t).unwrap();

        // time to decode 1 KB
        b.iter(|| {
            let bytes = 1024;
            for _ in 0..(bytes / MESSAGE_SIZE_BYTES) {
                st.decode(&mut ctx, &n).unwrap();
            }
        });
    }

    #[test]
    fn encode() {
        let mut n = BigNum::new().unwrap();
        let mut t = BigNum::new().unwrap();
        let mut ctx = BigNumContext::new().unwrap();

        // create encoding key

        generate(&mut ctx, &mut n, &mut t).unwrap();

        // encode random messages

        for _ in 0..10 {
            let mut s0 = BigNum::new().unwrap();
            let mut s1 = BigNum::new().unwrap();

            s0.rand(HALF_SIZE as i32, MsbOption::ONE, false).unwrap();
            s1.rand(HALF_SIZE as i32, MsbOption::ONE, false).unwrap();

            let mut st = State{
                s: [
                    s0.to_owned().unwrap(),
                    s1.to_owned().unwrap(),
                ]
            };

            st.encode(&mut ctx, &n, &t).unwrap();
            st.decode(&mut ctx, &n).unwrap();

            assert_eq!(s0, st.s[0]);
            assert_eq!(s1, st.s[1]);
        }
    }

    #[test]
    fn fdh_test() {
        let v = vec![
            0x00, 0x01, 0x02, 0x03,
            0x00, 0x01, 0x02, 0x03,
            0x00, 0x01, 0x02, 0x03,
            0x00, 0x01, 0x02, 0x03,
        ];

        let w = fdh(v.to_owned(), FDH_ROUNDS, false);
        let w = fdh(w, FDH_ROUNDS, true);

        assert_eq!(v, w);
    }

    #[test]
    fn split_join_test() {
        let m = [0u8; 1 << 10];
        let s = split(&m[..]);
        let n = join(&s[..]);
        assert_eq!(m[..], n[..]);
    }

}
