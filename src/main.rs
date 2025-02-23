use api::runtime_types::tangle_primitives::services::service::{
    BlueprintServiceManager, ServiceBlueprint,
};
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_std::UniformRand;
use blueprint_sdk as sdk;
use blueprint_sdk::alloy::network::EthereumWallet;
use blueprint_sdk::alloy::primitives::{Address, Bytes};
use blueprint_sdk::alloy::signers::local::PrivateKeySigner;
use blueprint_sdk::config::GadgetConfiguration;
use blueprint_sdk::contexts::keystore::KeystoreContext;
use blueprint_sdk::contexts::tangle::TangleClientContext;
use blueprint_sdk::keystore::backends::Backend;
use blueprint_sdk::runners::core::runner::BlueprintRunner;
use blueprint_sdk::runners::tangle::tangle::TangleConfig;
use blueprint_sdk::tangle_subxt::subxt::utils::AccountId32;
use blueprint_sdk::tangle_subxt::tangle_testnet_runtime::api;
use blueprint_sdk::utils::evm::get_wallet_provider_http;
use color_eyre::Result;
use gadget_crypto::sp_core::{SpEcdsa, SpSr25519};
use gadget_crypto::tangle_pair_signer::sp_core::Pair;
use silent_threshold_encryption::kzg::{PowersOfTau, KZG10};
use silent_timelock_encryption_blueprint::context::{ServiceContext, KEYPAIR_KEY};
use silent_timelock_encryption_blueprint::jobs::DecryptCiphertextEventHandler;
use silent_timelock_encryption_blueprint::setup::{setup, SilentThresholdEncryptionKeypair};
use silent_timelock_encryption_blueprint::SilentTimelockEncryptionBlueprint;

#[sdk::main(env)]
async fn main() -> Result<()> {
    let max_degree = 1 << 10;
    let tau = <Bn254 as Pairing>::ScalarField::rand(&mut ark_std::test_rng());
    let params =
        KZG10::<Bn254, DensePolynomial<<Bn254 as Pairing>::ScalarField>>::setup(max_degree, tau)
            .unwrap();

    let context = ServiceContext::new(
        env.clone(),
        params.clone(),
        env.protocol_settings.tangle().unwrap().service_id.unwrap(),
    )
    .await?;

    // Check if keypair exists in local db, otherwise generate and save it
    ensure_keypair_exists(&context, &env, params).await?;

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

async fn ensure_keypair_exists(
    context: &ServiceContext,
    env: &GadgetConfiguration,
    params: PowersOfTau<Bn254>,
) -> Result<()> {
    if context.secret_key_store.get(KEYPAIR_KEY).is_none() {
        let client = env.tangle_client().await?;
        let public = env.keystore().first_local::<SpSr25519>()?;
        let signer = env.keystore().get_secret::<SpSr25519>(&public)?;
        let operators = context.current_service_operators_ecdsa_keys().await?;
        let my_operator_position = operators
            .iter()
            .position(|op| *op.0 == AccountId32::from(signer.0.public().0))
            .expect("operator should be present for the service");

        let new_keypair =
            setup::<Bn254>(operators.len() as u32, my_operator_position as u32, &params)
                .expect("Failed to generate keypair");
        println!("Generated keypair for service");
        // Submit the STE public key to the blueprint contract
        let blueprint_id = context.blueprint_id()?;
        let blueprint_storage_key = api::storage().services().blueprints(blueprint_id);
        let blueprint: ServiceBlueprint = client
            .storage()
            .at_latest()
            .await?
            .fetch(&blueprint_storage_key)
            .await
            .map(|op| {
                if let Some(op) = op {
                    op.1
                } else {
                    panic!("Blueprint not found")
                }
            })?;

        let blueprint_contract_address = match blueprint.manager {
            BlueprintServiceManager::Evm(address) => Address::from(address.to_fixed_bytes()),
        };
        submit_ste_public_key(
            env,
            context.service_id,
            &new_keypair,
            blueprint_contract_address,
        )
        .await?;

        context.secret_key_store.set(KEYPAIR_KEY, new_keypair);
    }
    Ok(())
}

/// Submit the STE public key to the blueprint contract for the given service ID
async fn submit_ste_public_key(
    env: &GadgetConfiguration,
    service_id: u64,
    keypair: &SilentThresholdEncryptionKeypair,
    blueprint_contract_address: Address,
) -> Result<()> {
    let public_key = env.keystore().first_local::<SpEcdsa>()?;
    let secret_key = env.keystore().get_secret::<SpEcdsa>(&public_key)?;
    let signer_seed = PrivateKeySigner::from_slice(&secret_key.seed())?;
    let wallet = EthereumWallet::new(signer_seed);
    let provider = get_wallet_provider_http(&env.http_rpc_endpoint, wallet);
    let contract = SilentTimelockEncryptionBlueprint::new(blueprint_contract_address, provider);

    // Submit the public key
    contract
        .registerSTEPublicKey(
            service_id,
            Bytes::copy_from_slice(keypair.public_key.as_ref()),
        )
        .send()
        .await?
        .get_receipt()
        .await?;

    println!(
        "Successfully submitted STE public key for service ID {}",
        service_id
    );

    Ok(())
}
