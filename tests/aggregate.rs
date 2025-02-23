use ark_bn254::Bn254;
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_poly::univariate::DensePolynomial;
use ark_std::UniformRand;
use blueprint_sdk::logging;
use color_eyre::eyre;
use rand::thread_rng;
use round_based::sim::Simulation;
use silent_threshold_encryption::encryption::encrypt;
use silent_threshold_encryption::kzg::KZG10;
use silent_threshold_encryption::setup::SecretKey;
use silent_timelock_encryption_blueprint::decrypt::{DecryptState, Msg};
use silent_timelock_encryption_blueprint::setup::from_bytes;
use std::sync::Arc;

#[tokio::test]
async fn simulate_decryption() {
    logging::setup_log();
    setup_ste_keys().await;
}

async fn setup_ste_keys() -> Result<(), eyre::Error> {
    let max_degree = 1 << 3;
    let tau = <Bn254 as Pairing>::ScalarField::rand(&mut ark_std::test_rng());
    let params =
        KZG10::<Bn254, DensePolynomial<<Bn254 as Pairing>::ScalarField>>::setup(max_degree, tau)
            .unwrap();

    let n = 8usize;
    let t = 4usize;

    let mut parsed_ste_pk = vec![];
    let mut parsed_ste_sk = vec![];

    let mut rng = thread_rng();
    parsed_ste_sk.push(SecretKey::<Bn254>::new(&mut rng));
    parsed_ste_sk[0].nullify();
    parsed_ste_pk.push(parsed_ste_sk[0].get_pk(0, &params, n));

    for i in 1..n {
        let new_keypair = silent_timelock_encryption_blueprint::setup::setup::<Bn254>(
            n as u32, i as u32, &params,
        )
        .expect("Failed to generate keypair");

        let pk: silent_threshold_encryption::setup::PublicKey<Bn254> =
            silent_timelock_encryption_blueprint::setup::from_bytes(&new_keypair.public_key);

        let sk: silent_threshold_encryption::setup::SecretKey<Bn254> =
            silent_timelock_encryption_blueprint::setup::from_bytes(&new_keypair.secret_key);

        parsed_ste_pk.push(pk);
        parsed_ste_sk.push(sk);
    }

    let agg_key = silent_threshold_encryption::setup::AggregateKey::new(parsed_ste_pk, &params);

    let ct = encrypt(&agg_key, t, &params);

    let partial_decryptions = parsed_ste_sk
        .iter()
        .map(|sk| sk.partial_decryption(&ct))
        .collect::<Vec<_>>();

    let mut selector: Vec<bool> = Vec::new();
    for _ in 0..t + 1 {
        selector.push(true);
    }
    for _ in t + 1..n {
        selector.push(false);
    }

    let dec_key = silent_threshold_encryption::decryption::agg_dec(
        &partial_decryptions,
        &ct,
        &selector,
        &agg_key,
        &params,
    );

    assert_eq!(dec_key, ct.enc_key);

    // instantiate parties and simulate decryption
    let parsed_ste_sk = Arc::new(parsed_ste_sk);
    let ct = Arc::new(ct);
    let agg_key = Arc::new(agg_key);
    let params = Arc::new(params);

    let mut simulation = Simulation::<_, Msg>::empty();
    for i in 0..n {
        let ct_clone = Arc::clone(&ct); // Clone the Arc for the async block
        let parsed_ste_sk_clone = Arc::clone(&parsed_ste_sk);
        let agg_key_clone = Arc::clone(&agg_key);
        let params_clone = Arc::clone(&params);
        simulation.add_async_party(|party| async move {
            let output = silent_timelock_encryption_blueprint::decrypt::threshold_decrypt_protocol(
                party,
                i as u16,
                t as u16,
                n as u16,
                &parsed_ste_sk_clone[i],
                &ct_clone,
                &agg_key_clone,
                &params_clone,
            )
            .await
            .unwrap();
            Result::<_, eyre::Error>::Ok(output)
        });
    }

    let mut outputs = Vec::with_capacity(n as usize);
    let tasks = simulation.run()?;
    for task in tasks {
        outputs.push(task);
    }
    let outputs = outputs.into_iter().collect::<Result<Vec<_>, _>>()?;

    let dec_key_bytes = outputs[0].decryption_result.as_ref().unwrap();
    let dec_key: PairingOutput<Bn254> = from_bytes(dec_key_bytes);
    assert_eq!(dec_key, ct.enc_key);

    println!("Tasks completed");

    Ok(())
}
