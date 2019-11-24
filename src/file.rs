use std::mem;

use super::misc::expand;
use super::File;

const FDH_ROUNDS: usize = 3;

use super::Shard;
use super::SHARD_SIZE;

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
        let length = data.len();
        let mut data = data.to_owned();

        /*
        // append randomness

        let mut rand = [0u8; 16];

        rand_bytes(&mut rand).unwrap();
        data.extend(&rand[..]);
        */

        // extend to multiple of shard size

        while data.len() % SHARD_SIZE != 0 {
            data.push(0x0);
        }
        assert_eq!(data.len() % SHARD_SIZE, 0);

        // full-domain hashing

        let data = fdh(data, FDH_ROUNDS, false);

        // split into fixed-sized shards

        let num_shards = data.len() / SHARD_SIZE;
        let mut shards = Vec::with_capacity(num_shards);
        assert!(num_shards < 1 << 16);

        for idx in 0..num_shards {
            let l = idx * SHARD_SIZE;
            let r = l + SHARD_SIZE;
            shards.push(Shard::new(idx as u16, &data[l..r]));
        }

        File { length, shards }
    }

    pub fn unpack(&self) -> Vec<u8> {
        // join all states

        let mut data = Vec::with_capacity(self.shards.len() * SHARD_SIZE);
        for st in &self.shards {
            data.extend(st.unpack());
        }

        // apply full domain hashing

        let mut data = fdh(data, FDH_ROUNDS, true);
        data.truncate(self.length);
        data
    }
}
