#![feature(test)]

extern crate test;

mod file;
mod misc;
mod rs;
mod rsa;

use openssl::bn::BigNum;

pub use rsa::{DecodingKey, EncodingKey};

#[derive(Debug)]
pub struct Shard {
    pub(crate) idx: u16, // index of the shard (we use RS codes over GF(2^16), so no more than 2^16 shards)
    pub(crate) s: [BigNum; 2], // the data
}

impl Clone for Shard {
    fn clone(&self) -> Self {
        let s0 = self.s[0].to_owned().unwrap();
        let s1 = self.s[1].to_owned().unwrap();

        Shard {
            idx: self.idx,
            s: [s0, s1],
        }
    }
}

#[derive(Debug)]
pub struct File {
    pub(crate) shards: Vec<Shard>,
}

// group size
const PRIME_SIZE: usize = 1025;
const MODULUS_SIZE: usize = 2 * PRIME_SIZE;

// message always slightly smaller to ensure that it is contained
const HALF_SIZE: usize = 2048;
const HALF_SIZE_BYTES: usize = HALF_SIZE / 8;
const MESSAGE_SIZE: usize = 2 * HALF_SIZE;
const MESSAGE_SIZE_BYTES: usize = 2 * HALF_SIZE_BYTES;
