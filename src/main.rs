use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_std::UniformRand;
use color_eyre::Result;
use gadget_sdk as sdk;
use sdk::ctx::ServicesContext;
use sdk::runners::tangle::TangleConfig;
use sdk::runners::BlueprintRunner;
use sdk::subxt_core::tx::signer::Signer;
use silent_threshold_encryption::kzg::KZG10;
use silent_timelock_encryption_blueprint::context::{ServiceContext, KEYPAIR_KEY};
use silent_timelock_encryption_blueprint::setup::setup;
use silent_timelock_encryption_blueprint::DecryptCiphertextEventHandler;

#[sdk::main(env)]
async fn main() -> Result<()> {
    let max_degree = 1 << 10;
    let tau = <Bn254 as Pairing>::ScalarField::rand(&mut ark_std::test_rng());
    let params =
        KZG10::<Bn254, DensePolynomial<<Bn254 as Pairing>::ScalarField>>::setup(max_degree, tau)
            .unwrap();

    let context = ServiceContext::new(env.clone(), params.clone())?;

    // Check if keypair exists in local db, otherwise generate and save it
    match context.secret_key_store.get(KEYPAIR_KEY) {
        Some(_) => {}
        _ => {
            let client = env.client().await?;
            let signer = env.first_sr25519_signer()?;
            let operators = context.current_service_operators(&client).await?;
            let my_operator_position = operators
                .iter()
                .position(|op| op.0 == signer.account_id())
                .expect("operator should be present for the service");
            let new_keypair =
                setup::<Bn254>(operators.len() as u32, my_operator_position as u32, params)
                    .expect("Failed to generate keypair");

            context.secret_key_store.set(KEYPAIR_KEY, new_keypair);
        }
    };

    tracing::info!("Generated keypair for service");

    // Create the event handler from the job
    let decrypt_ciphertext = DecryptCiphertextEventHandler::new(&env, context.clone()).await?;

    tracing::info!("Starting the event watcher ...");
    let tangle_config = TangleConfig::default();
    BlueprintRunner::new(tangle_config, env)
        .job(decrypt_ciphertext)
        .run()
        .await?;

    tracing::info!("Exiting...");
    Ok(())
}
