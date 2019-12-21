#![feature(test)]

extern crate test;

mod file;
mod misc;
mod rs;
mod rsa;

#[cfg(test)]
mod tests;

use openssl::bn::BigNum;
use std::fmt;
use std::mem::MaybeUninit;

pub use rsa::{DecodingKey, EncodingKey};

// group size
const PRIME_SIZE: usize = 1025;
const MODULUS_SIZE: usize = 2 * PRIME_SIZE;

// message always slightly smaller to ensure that it is contained
const BLOCK_HALF_SIZE_BITS: usize = 8 * (MODULUS_SIZE / 8);
const BLOCK_HALF_SIZE: usize = BLOCK_HALF_SIZE_BITS / 8;
const BLOCK_SIZE: usize = 2 * BLOCK_HALF_SIZE;

const SHARD_SIZE: usize = 1024; // each shard is 1KB
const SHARD_ELEMS: usize = SHARD_SIZE / 2; // shard elements are GF(2^16)
const SHARD_BLOCKS: usize = SHARD_SIZE / BLOCK_SIZE;

#[derive(Copy, Clone)]
pub struct Shard {
    pub(crate) idx: u16,
    pub(crate) coords: [[u8; 2]; SHARD_SIZE / 2],
}

#[derive(Debug)]
pub(crate) struct EncodeBlock {
    pub(crate) s: [BigNum; 2],
}

impl Default for EncodeBlock {
    fn default() -> Self {
        EncodeBlock {
            s: [BigNum::new().unwrap(), BigNum::new().unwrap()],
        }
    }
}

#[derive(Debug, Clone)]
pub struct EncodedShard {
    pub(crate) idx: u16,
    pub(crate) blocks: [EncodeBlock; SHARD_BLOCKS],
}

#[derive(Debug)]
pub struct File {
    pub(crate) length: usize,
    pub(crate) shards: Vec<Shard>,
}

pub struct Header {
    pub(crate) length: usize, // length of file
}

impl Header {
    /// Returns the number of shards needed to reconstruct the file
    pub fn shards(&self) -> usize {
        let n = self.length / SHARD_SIZE;
        if self.length % SHARD_SIZE != 0 {
            n + 1
        } else {
            n
        }
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Header {{ length = {}, data-shards (dimension) = {} }}",
            self.length,
            self.shards()
        )
    }
}

impl Shard {
    pub(crate) fn new(idx: u16, bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), SHARD_SIZE);
        debug_assert_eq!(bytes.len(), SHARD_ELEMS * 2);

        let mut shard = Shard {
            idx,
            coords: [Default::default(); SHARD_ELEMS],
        };

        for i in 0..shard.coords.len() {
            shard.coords[i][0] = bytes[i * 2];
            shard.coords[i][1] = bytes[i * 2 + 1];
        }
        shard
    }

    pub(crate) fn unpack(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(self.coords.len() * 2);
        for c in self.coords.iter() {
            bytes.push(c[0]);
            bytes.push(c[1]);
        }
        bytes
    }

    pub fn pack(&self) -> EncodedShard {
        // unpack GF(2^16) elements to bytes
        let bytes = self.unpack();

        // split into encode blocks
        let mut blocks: [EncodeBlock; SHARD_BLOCKS] =
            unsafe { MaybeUninit::zeroed().assume_init() };

        for i in 0..SHARD_BLOCKS {
            // calculate byte ranges for block
            let l = i * BLOCK_SIZE;
            let m = l + BLOCK_HALF_SIZE;
            let r = (i + 1) * BLOCK_SIZE;

            // pack bytes into bignum integers
            let s0 = BigNum::from_slice(&bytes[l..m]).unwrap();
            let s1 = BigNum::from_slice(&bytes[m..r]).unwrap();
            blocks[i] = EncodeBlock { s: [s0, s1] };
        }

        EncodedShard {
            blocks,
            idx: self.idx,
        }
    }
}

impl EncodedShard {
    pub fn unpack(&self) -> Shard {
        let mut bytes = Vec::with_capacity(SHARD_SIZE);
        let mut push = |n: &BigNum| {
            let bs = n.to_vec();
            for _ in bs.len()..BLOCK_HALF_SIZE {
                bytes.push(0x0);
            }
            bytes.extend(&bs[..]);
            debug_assert_eq!(bytes.len() % BLOCK_HALF_SIZE, 0);
        };

        // unpack bignum integer to bytes
        for i in 0..SHARD_BLOCKS {
            push(&self.blocks[i].s[0]);
            push(&self.blocks[i].s[1]);
        }
        debug_assert_eq!(bytes.len() % BLOCK_SIZE, 0);
        debug_assert_eq!(bytes.len(), SHARD_SIZE);

        // pack bytes into GF(2^16) elements
        Shard::new(self.idx, &bytes)
    }
}

impl fmt::Debug for Shard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Shard {{ idx: {}, coords: {:?} }}",
            self.idx,
            &self.coords[..]
        )
    }
}

impl Clone for EncodeBlock {
    fn clone(&self) -> Self {
        let s0 = self.s[0].to_owned().unwrap();
        let s1 = self.s[1].to_owned().unwrap();
        EncodeBlock { s: [s0, s1] }
    }
}
