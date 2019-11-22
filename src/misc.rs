use openssl::sha::Sha256;
use openssl::symm::{encrypt, Cipher};

/* Expand
 *
 *
 */
pub fn expand(tweak: &[u8], value: &[u8], size: usize) -> Vec<u8> {
    // hash the input
    let mut hsh = Sha256::new();
    hsh.update(tweak);
    hsh.update(value);
    let key = hsh.finish();

    // allocate result buffer
    let mut zero: Vec<u8> = Vec::with_capacity(size);
    zero.resize(size, 0);

    // stretch into a large random number using AES-CTR
    let iv = [0u8; 16];
    let cipher = Cipher::aes_256_ctr();
    encrypt(cipher, &key[..], Some(&iv[..]), &zero[..]).unwrap()
}
