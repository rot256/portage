use rand::Rng;
use test::Bencher;

use super::*;

#[bench]
fn encode(b: &mut Bencher) {
    let mut sk = EncodingKey::new();
    let mut bytes1 = Vec::with_capacity(1024);
    bytes1.resize(bytes1.capacity(), 0u8);

    let file = File::new(&bytes1[..]);
    let (_, shards) = file.shards(0);

    let mut enc: Vec<EncodedShard> = shards.into_iter().map(|s| s.pack()).collect();

    b.iter(|| {
        for s in enc.iter_mut() {
            sk.encode(s)
        }
    });
}

#[bench]
fn decode(b: &mut Bencher) {
    let sk = EncodingKey::new();
    let mut pk = sk.decoding();
    let mut bytes1 = Vec::with_capacity(1024);
    bytes1.resize(bytes1.capacity(), 0u8);

    let file = File::new(&bytes1[..]);
    let (_, shards) = file.shards(0);

    let mut enc: Vec<EncodedShard> = shards.into_iter().map(|s| s.pack()).collect();

    b.iter(|| {
        for s in enc.iter_mut() {
            pk.decode(s)
        }
    });
}

#[test]
fn encode_decode() {
    // generate new encoding / decoding key
    let mut sk = EncodingKey::new();
    let mut pk = sk.decoding();

    // generate a random input file
    let mut rng = rand::thread_rng();
    let size: usize = rng.gen::<usize>() % 10240;
    let mut original = Vec::with_capacity(size);
    for _ in 0..size {
        original.push(rng.gen());
    }

    // create file object and split into shards
    let file = File::new(&original[..]);
    let expand: usize = rng.gen::<usize>() % 20;
    let (header, shards) = file.shards(expand);
    assert_eq!(shards.len(), header.shards() + expand);

    // encode each shard
    let mut enc: Vec<EncodedShard> = shards
        .into_iter()
        .map(|s| {
            let mut e = s.pack();
            sk.encode(&mut e);
            e
        })
        .collect();
    assert_eq!(enc.len(), header.shards() + expand);

    // lose the maximum number
    for _ in 0..expand {
        let idx: usize = rng.gen();
        enc.remove(idx % enc.len());
    }

    // decode the rest
    let dec: Vec<Shard> = enc
        .into_iter()
        .map(|mut e| {
            pk.decode(&mut e);
            e.unpack()
        })
        .collect();

    // recover the file from the remaining shards
    let file2 = File::reconstruct(&header, &dec[..]).unwrap();
    let recover = file2.unpack();

    // check that we succesfully recovered
    assert_eq!(&original[..], &recover[..]);
}
