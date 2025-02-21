use alloy_network::EthereumWallet;
use alloy_primitives::{Address, Bytes};
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_std::UniformRand;
use color_eyre::Result;
use gadget_sdk::tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_primitives::services::{BlueprintServiceManager, ServiceBlueprint};
use gadget_sdk as sdk;
use gadget_sdk::config::StdGadgetConfiguration;
use gadget_sdk::ext::tangle_subxt::tangle_testnet_runtime::api;
use gadget_sdk::utils::evm::{get_provider_http, get_wallet_provider_http};
use sdk::contexts::ServicesContext;
use sdk::runners::tangle::TangleConfig;
use sdk::runners::BlueprintRunner;
use sdk::subxt_core::tx::signer::Signer;
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

    let context = ServiceContext::new(env.clone(), params.clone())?;

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
    env: &StdGadgetConfiguration,
    params: PowersOfTau<Bn254>,
) -> Result<()> {
    if context.secret_key_store.get(KEYPAIR_KEY).is_none() {
        let client = env.client().await?;
        let signer = env.first_sr25519_signer()?;
        let service_id = env.service_id().unwrap();
        let operators = context.current_service_operators(&client).await?;
        let my_operator_position = operators
            .iter()
            .position(|op| op.0 == signer.account_id())
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
        submit_ste_public_key(env, service_id, &new_keypair, blueprint_contract_address).await?;

        context.secret_key_store.set(KEYPAIR_KEY, new_keypair);
    }
    Ok(())
}

/// Submit the STE public key to the blueprint contract for the given service ID
async fn submit_ste_public_key(
    env: &StdGadgetConfiguration,
    service_id: u64,
    keypair: &SilentThresholdEncryptionKeypair,
    blueprint_contract_address: Address,
) -> Result<()> {
    let signer = env.first_ecdsa_signer()?.alloy_key()?;
    let wallet = EthereumWallet::from(signer);
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
