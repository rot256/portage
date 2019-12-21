<img src="icon.png" align="right" height="300" width="300"/>

# Portage

Portage is a Proof-of-Concept implementation of a replica encoding scheme without timing assumptions, combined with erasure encoding (Reed-Solomon codes).
The underlaying replica encoding is described in [Proofs of Replicated Storage Without Timing Assumptions](https://eprint.iacr.org/2018/654.pdf),
which only considers simple duplication of the same file (a repetition code).

## What is it?

The goal of Portage specifically or replica encoding more generally,
is to allow the transformation of a file into a more redundant format,
which can then be uploaded to an untrusted party.
This untrusted party should then be unable to "deduplicate" or compress the redundant file,
however the file should still be publicly retrievable
e.g. no secret key material is used to "decrypt" the redundant format.

## Example application

Imagine you are hosting a decentralized website and want a number of rational selfish nodes to provide this hosting.
Furthermore you want redundancy, such that if some fraction of the hired nodes fail the resource remains available.
A naive solution is to upload the same file to all the nodes and then enable the nodes to claim some funds
as long as they show that the file remains available (e.g. using a "Proof-of-Storage").
However, this  incentivises the nodes to collude and store a single copy, since this is cheaper, yet still claim the reward for storing multiple individual copies.

To solve this with a replication encoding scheme you run some algorithms split,
which takes a message and the number of redundant shares (length of the code - dimension) `R >= 0`:

```
w_1, ..., w_l <- Split(m, R)
```

Generate an encoding and decoding key:

```
k_enc, k_dec <- Generate()
```

Then encode each "shard" separately:

```
r_i <- Encode(k_enc, w_1)
```

The goal of the replica encoding is to ensure the "incompressibility" of `r_1, ..., r_l`, even when given `k_dec`.

Using the decoding key a subset of "shards" can be decoded separately (by a client wishing to fetch the
file):

```
w_i <- Decode(k_dec, r_i)
```

And the original message reconstructed, e.g.

```
m <- Reconstruct(w_3, w_5, w_7, w_13, ...)
```

Note that splitting and encoding is separate,
this allows multiple different trusted encoders to partake in the encoding of a single file.
Since the encoding is rather slow, it might be advantageous to outsource this work to a
set of nodes of which some large fraction is assumed honest.
Splitting is deterministic such that distinct uploaders splitting the same file
can potentially share the same codewords during reconstruction,
e.g. it is possible to pay for upkeep of a fraction of the entire file.

## Example usage

```rust
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

// encode each shard
let mut enc: Vec<EncodedShard> = shards
    .into_iter()
    .map(|s| {
        let mut e = s.pack();
        sk.encode(&mut e);
        e
    })
    .collect();

/* send the encoded shards to remote storage */

// lose some number of shards
let lose = rng.gen::<usize>() % (expand + 1);
for _ in 0..lose {
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
```

## Benchmark

Encoding is quite slow, however decoding is reasonably fast:



