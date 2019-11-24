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
    let mut sk = EncodingKey::new();
    let mut pk = sk.decoding();

    let mut bytes1 = Vec::with_capacity(1024);
    bytes1.resize(bytes1.capacity(), 0u8);

    let file = File::new(&bytes1[..]);
    let expand = 2;
    let (header, shards) = file.shards(expand);
    assert_eq!(shards.len(), header.shards() + expand);

    let enc = shards.into_iter().map(|s| {
        let mut e = s.pack();
        sk.encode(&mut e);
        e
    });

    let dec: Vec<Shard> = enc
        .into_iter()
        .map(|mut e| {
            pk.decode(&mut e);
            e.unpack()
        })
        .collect();

    let file2 = File::reconstruct(&header, &dec[..]).unwrap();
    let bytes2 = file2.unpack();

    assert_eq!(&bytes2[..], &bytes1[..]);
}
