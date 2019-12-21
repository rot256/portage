use portage::*;
use std::thread;

const DATA: usize = 1024 * 1024;
const BLOCK: usize = 1024;
const WORK: usize = DATA / BLOCK;
const WORKERS: usize = 8;

pub fn main() {
    let sk = EncodingKey::new();
    let mut bytes1 = Vec::with_capacity(BLOCK);
    bytes1.resize(bytes1.capacity(), 0u8);

    let file = File::new(&bytes1[..]);
    let (_, shards) = file.shards(WORKERS - 1);

    let mut enc: Vec<EncodedShard> = shards.into_iter().map(|s| s.pack()).collect();
    let mut handles = vec![];

    for _i in 0..WORKERS {
        let mut sk = sk.clone();
        let mut shard = enc.pop().unwrap();
        handles.push(thread::spawn(move || {
            for i in 0..(WORK / WORKERS) {
                println!("enc {} / {}", i, (WORK / WORKERS));
                sk.encode(&mut shard);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}
