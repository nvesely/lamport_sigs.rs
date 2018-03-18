use ring::digest::{Algorithm, SHA256, SHA512};
use test::Bencher;

use PrivateKey;
use PublicKey;

#[allow(non_upper_case_globals)]
static digest_256: &'static Algorithm = &SHA256;

#[allow(non_upper_case_globals)]
static digest_512: &'static Algorithm = &SHA512;

#[cfg(test)]
#[test]
fn test_public_key_length_256() {
    let pk = PrivateKey::new(digest_256);
    assert!(pk.public_key().one_values.len() == 256 && pk.public_key().zero_values.len() == 256);
}

#[test]
fn test_public_key_length_512() {
    let pk = PrivateKey::new(digest_512);
    assert!(pk.public_key().one_values.len() == 512 && pk.public_key().zero_values.len() == 512);
}

// #[bench]
// fn bench_public_key_gen_length_256() {
//     let pk = PrivateKey::new(digest_256);
// }
//
// #[bench]
// fn bench_public_key_gen_length_512() {
//     let pk = PrivateKey::new(digest_512);
// }

#[test]
fn test_distinctive_successive_keygen() {
    let mut past_buff = PrivateKey::new(digest_512);
    for _ in 0..100 {
        let buffer = PrivateKey::new(digest_512);
        assert!(past_buff != buffer);
        past_buff = buffer;
    }
}

#[test]
fn test_sign_verif() {
    let mut priv_key = PrivateKey::new(digest_512);
    let data = "Hello World".as_bytes();
    let signature = priv_key.sign(data).unwrap();

    let pub_key = priv_key.public_key();

    assert!(pub_key.verify_signature(&signature, data));
}

#[bench]
fn bench_sign_verif(b: &mut Bencher) {
    let mut priv_key = PrivateKey::new(digest_512);
    let data = "Hello World".as_bytes();
    let signature = priv_key.sign(data).unwrap();
    let pub_key = priv_key.public_key();
    b.iter(|| pub_key.verify_signature(&signature, data));
}

#[test]
fn test_sign_verif_sig_wrong_size() {
    let mut priv_key = PrivateKey::new(digest_512);
    let data = "Hello World".as_bytes();
    let mut too_short = priv_key.sign(data).unwrap();
    let extra = too_short.pop();

    let pub_key = priv_key.public_key();

    assert!(!pub_key.verify_signature(&too_short, data));

    let mut priv_key = PrivateKey::new(digest_512);
    let data = "Hello World".as_bytes();
    let mut too_long = priv_key.sign(data).unwrap();
    too_long.extend(extra);

    assert!(!pub_key.verify_signature(&too_long, data));
}

#[test]
fn test_sign_verif_fail() {
    let mut priv_key = PrivateKey::new(digest_512);
    let data = "Hello Word".as_bytes();
    let signature = priv_key.sign(data).unwrap();

    let pub_key = priv_key.public_key();
    let data2 = "Hello".as_bytes();
    assert!(!pub_key.verify_signature(&signature, data2));
}

// `bench_sign_verif` and `bench_sign_verif_fail`'s runtime should be
// within each other's margin of error.
#[bench]
fn bench_sign_verif_fail(b: &mut Bencher) {
    let mut priv_key = PrivateKey::new(digest_512);
    let data = "Hello Word".as_bytes();
    let signature = priv_key.sign(data).unwrap();
    let pub_key = priv_key.public_key();
    let data2 = "Hello".as_bytes();
    b.iter(|| pub_key.verify_signature(&signature, data2));
}

#[test]
fn test_serialization() {
    let pub_key = PrivateKey::new(digest_512).public_key();
    let bytes = pub_key.to_bytes();
    let recovered_pub_key = PublicKey::from_vec(bytes, digest_512).unwrap();

    assert_eq!(pub_key.one_values, recovered_pub_key.one_values);
    assert_eq!(pub_key.zero_values, recovered_pub_key.zero_values);
}

fn test_serialization_wrong_size_key() {
    let pub_key = PrivateKey::new(digest_512).public_key();
    let mut too_short = pub_key.to_bytes();
    let extra = too_short.pop();
    assert!(PublicKey::from_vec(too_short, digest_512).is_none());

    let pub_key = PrivateKey::new(digest_512).public_key();
    let mut too_long = pub_key.to_bytes();
    too_long.extend(extra);
    assert!(PublicKey::from_vec(too_long, digest_512).is_none());
}

#[bench]
fn bench_serialization_to_bytes(b: &mut Bencher) {
    let pub_key = PrivateKey::new(digest_512).public_key();
    b.iter(|| pub_key.to_bytes());
}

#[bench]
fn bench_serialization_from_vec(b: &mut Bencher) {
    let pub_key = PrivateKey::new(digest_512).public_key();
    let bytes = pub_key.to_bytes();
    b.iter(|| PublicKey::from_vec(bytes.clone(), digest_512));
}

#[test]
#[should_panic]
fn test_serialization_panic() {
    let pub_key = PrivateKey::new(digest_512).public_key();
    let mut bytes = pub_key.to_bytes();
    bytes.pop();
    let _recovered_pub_key = PublicKey::from_vec(bytes, digest_512).unwrap();
}
