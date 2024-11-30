use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_std::UniformRand;
use blueprint_test_utils::setup_log;
use proptest::prelude::*;
use round_based::simulation::Simulation;
use silent_threshold_encryption::encryption::encrypt;
use silent_threshold_encryption::kzg::KZG10;
use silent_timelock_encryption_blueprint::context::ServiceContext;
use silent_timelock_encryption_blueprint::decrypt::Msg;
use std::borrow::Borrow;
use test_strategy::proptest;
use test_strategy::Arbitrary;

// use rand::rngs::StdRng;
// use rand::SeedableRng;

#[derive(Arbitrary, Debug, Clone, Copy)]
struct TestInputArgs {
    #[strategy(3..10u16)]
    n: u16,
    #[strategy(2..#n)]
    t: u16,
}

#[proptest(async = "tokio", cases = 20, fork = true)]
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

    let mut simulation = Simulation::<Msg>::new();
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

    let _dec_key = silent_threshold_encryption::decryption::agg_dec(
        &partial_decryptions,
        &ct,
        &selector,
        &agg_key,
        &params,
    );

    assert_eq!(_dec_key, ct.enc_key);

    // instantiate parties and simulate decryption
}

// async fn run_keygen<C>(args: &TestInputArgs) -> Result<(), TestCaseError>
// where
//     C: Ciphersuite + Send + Unpin,
//     <<C as Ciphersuite>::Group as Group>::Element: Send + Unpin,
//     <<<C as Ciphersuite>::Group as Group>::Field as frost_core::Field>::Scalar: Send + Unpin,
// {
//     let TestInputArgs { n, t } = *args;
//     prop_assume!(frost_core::keys::validate_num_of_signers::<C>(t, n).is_ok());

//     eprintln!("Running a {} {t}-out-of-{n} Keygen", C::ID);
//     let mut simulation = Simulation::<Msg<C>>::new();
//     let mut tasks = vec![];
//     for i in 0..n {
//         let party = simulation.add_party();
//         let output = tokio::spawn(async move {
//             let rng = &mut StdRng::seed_from_u64(u64::from(i + 1));
//             let mut tracer = PerfProfiler::new();
//             let output = run(rng, t, n, i, party, Some(tracer.borrow_mut())).await?;
//             let report = tracer.get_report().unwrap();
//             eprintln!("Party {} report: {}\n", i, report);
//             Result::<_, Error<C>>::Ok(output)
//         });
//         tasks.push(output);
//     }

//     let mut outputs = Vec::with_capacity(tasks.len());
//     for task in tasks {
//         outputs.push(task.await.unwrap());
//     }
//     let outputs = outputs.into_iter().collect::<Result<Vec<_>, _>>()?;
//     // Assert that all parties outputed the same public key
//     let (_, pubkey_pkg) = &outputs[0];
//     for (_, other_pubkey_pkg) in outputs.iter().skip(1) {
//         prop_assert_eq!(pubkey_pkg, other_pubkey_pkg);
//     }

//     Ok(())
// }
