use std::mem;

use super::misc::expand;
use super::File;
use openssl::bn::BigNum;

const FDH_ROUNDS: usize = 3;

use super::Shard;
use super::{HALF_SIZE_BYTES, MESSAGE_SIZE_BYTES};

fn fdh(data: Vec<u8>, rounds: usize, reverse: bool) -> Vec<u8> {
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

impl File {
    pub fn new(data: &[u8]) -> File {
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

        let num_shards = data.len() / MESSAGE_SIZE_BYTES;
        let mut shards = Vec::with_capacity(num_shards);
        assert!(num_shards < 1 << 16);

        for idx in 0..num_shards {
            let l = idx * MESSAGE_SIZE_BYTES;
            let m = l + HALF_SIZE_BYTES;
            let r = m + HALF_SIZE_BYTES;
            let s0 = BigNum::from_slice(&data[l..m]).unwrap();
            let s1 = BigNum::from_slice(&data[m..r]).unwrap();
            shards.push(Shard {
                idx: idx as u16,
                s: [s0, s1],
            })
        }

        File { shards }
    }

    pub fn unpack(&self) -> Vec<u8> {
        // join all states

        let mut data = Vec::with_capacity(self.shards.len() * MESSAGE_SIZE_BYTES);

        for st in &self.shards {
            data.extend(st.s[0].to_vec());
            data.extend(st.s[1].to_vec());
        }

        // apply full domain hashing

        let mut data = fdh(data, FDH_ROUNDS, true);

        // remove padding

        while let Some(0) = data.pop() {}

        data
    }
}
