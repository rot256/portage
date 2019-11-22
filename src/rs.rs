use reed_solomon_erasure::galois_16::Field;

use super::{File, Shard};

impl File {
    pub fn get(&self, idx: u16) -> Shard {
        // if it is one of the first it is simply from the file
        let i: usize = idx as usize;
        if i < self.shards.len() {
            return self.shards[i].clone();
        }

        // otherwise use RS coding to extend and create new shards

        unreachable!();
    }
}
