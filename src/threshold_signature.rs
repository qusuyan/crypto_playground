use std::collections::BTreeMap;

use rand::prelude::*;
use rand_chacha::ChaCha8Rng;

use frost_secp256k1 as frost;

pub fn measure(msg_len: usize, n: u16, k: u16, seed: u64) {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let (signing_shares, pubkey_package) =
        frost::keys::generate_with_dealer(n, k, frost::keys::IdentifierList::Default, &mut rng)
            .unwrap();
    let group_pubkey = pubkey_package.verifying_key();

    // ROUND1: generating nonce and commitments for signing key
    let mut signing_keys = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for (id, secret_share) in signing_shares {
        let key_package = frost::keys::KeyPackage::try_from(secret_share).unwrap();
        let (nonce, commitment) = frost::round1::commit(key_package.signing_share(), &mut rng);
        signing_keys.insert(id, (key_package, nonce));
        commitments.insert(id, commitment);
    }

    // generate message to sign
    let mut msg: Vec<u8> = Vec::with_capacity(msg_len);
    for _ in 0..msg_len {
        msg.push(rng.r#gen());
    }

    // ROUND2: signing
    let signing_package = frost::SigningPackage::new(commitments, &msg);
    let mut signatures_shares = BTreeMap::new();
    for (id, (key_package, nonce)) in signing_keys.iter() {
        let signature_share = frost::round2::sign(&signing_package, nonce, key_package).unwrap();
        signatures_shares.insert(*id, signature_share);
    }

    // combine into group signature
    let group_signature =
        frost::aggregate(&signing_package, &signatures_shares, &pubkey_package).unwrap();

    // verify
    group_pubkey.verify(&msg, &group_signature).unwrap();
    println!("Success")
}
