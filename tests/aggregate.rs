use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_std::UniformRand;
use blueprint_test_utils::setup_log;
use gadget_sdk::tracer::PerfProfiler;
use round_based::simulation::Simulation;
use silent_threshold_encryption::encryption::encrypt;
use silent_threshold_encryption::kzg::KZG10;
use silent_timelock_encryption_blueprint::decrypt::Msg;
use std::sync::Arc;
use tokio::time::error::Error;

#[tokio::test]
async fn it_works() {
    setup_log();
    setup_ste_keys().await;
}

async fn setup_ste_keys() {
    let max_degree = 1 << 3;
    let tau = <Bn254 as Pairing>::ScalarField::rand(&mut ark_std::test_rng());
    let params =
        KZG10::<Bn254, DensePolynomial<<Bn254 as Pairing>::ScalarField>>::setup(max_degree, tau)
            .unwrap();

    let n = 8usize;
    let t = 4usize;

    let mut parsed_ste_pk = vec![];
    let mut parsed_ste_sk = vec![];
    for i in 0..n {
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
    println!("Instantiating parties and simulating decryption\n");

    let parsed_ste_sk = Arc::new(parsed_ste_sk);
    let ct = Arc::new(ct);
    let agg_key = Arc::new(agg_key);
    let params = Arc::new(params);

    let mut simulation = Simulation::<Msg>::new();
    let mut tasks = vec![];
    for i in 0..n {
        let party = simulation.add_party();
        let output = tokio::spawn({
            let ct_clone = Arc::clone(&ct); // Clone the Arc for the async block
            let parsed_ste_sk_clone = Arc::clone(&parsed_ste_sk);
            let agg_key_clone = Arc::clone(&agg_key);
            let params_clone = Arc::clone(&params);
            async move {
                let output =
                    silent_timelock_encryption_blueprint::decrypt::threshold_decrypt_protocol(
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
                Result::<_, Error>::Ok(output)
            }
        });
        tasks.push(output);
    }

    let mut outputs = Vec::with_capacity(tasks.len());
    for task in tasks {
        outputs.push(task.await.unwrap().unwrap());
    }
}

// async fn run_signing<C>(args: &TestInputArgs) -> Result<(), TestCaseError>
//     where
//         C: Ciphersuite + Send + Unpin + Sync,
//         <<C as Ciphersuite>::Group as Group>::Element: Send + Unpin + Sync,
//         <<<C as Ciphersuite>::Group as Group>::Field as frost_core::Field>::Scalar:
//             Send + Unpin + Sync,
//     {
//         let TestInputArgs { n, t, msg } = *args;
//         let keygen_output = run_keygen::<C>(args).await?;
//         let public_key = keygen_output
//             .values()
//             .map(|(_, pkg)| pkg.clone())
//             .next()
//             .unwrap();
//         let rng = &mut StdRng::from_seed(msg);
//         let signers = keygen_output
//             .into_iter()
//             .choose_multiple(rng, usize::from(t));
//         let signer_set = signers.iter().map(|(i, _)| *i).collect::<Vec<_>>();

//         eprintln!("Running a {} {t}-out-of-{n} Signing", C::ID);
//         let mut simulation = Simulation::<Msg<C>>::new();
//         let mut tasks = vec![];
//         for (i, (key_pkg, pub_key_pkg)) in signers {
//             let party = simulation.add_party();
//             let signer_set = signer_set.clone();
//             let msg = msg.to_vec();
//             let output = tokio::spawn(async move {
//                 let rng = &mut StdRng::seed_from_u64(u64::from(i + 1));
//                 let mut tracer = PerfProfiler::new();
//                 let output = run(
//                     rng,
//                     &key_pkg,
//                     &pub_key_pkg,
//                     &signer_set,
//                     &msg,
//                     party,
//                     Some(tracer.borrow_mut()),
//                 )
//                 .await?;
//                 let report = tracer.get_report().unwrap();
//                 eprintln!("Party {} report: {}\n", i, report);
//                 Result::<_, Error<C>>::Ok((i, output))
//             });
//             tasks.push(output);
//         }

//         let mut outputs = Vec::with_capacity(tasks.len());
//         for task in tasks {
//             outputs.push(task.await.unwrap());
//         }
//         let outputs = outputs.into_iter().collect::<Result<BTreeMap<_, _>, _>>()?;
//         // Assert that all parties produced a valid signature
//         let signature = outputs.values().next().unwrap();
//         C::verify_signature(&msg, signature, public_key.verifying_key())?;
//         for other_signature in outputs.values().skip(1) {
//             prop_assert_eq!(signature, other_signature);
//         }

//         Ok(())
//     }
