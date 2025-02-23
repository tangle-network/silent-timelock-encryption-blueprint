pub mod context;
pub mod decrypt;
pub mod jobs;
pub mod setup;
use blueprint_sdk::alloy::sol;
use serde::{Deserialize, Serialize};

sol!(
    #[sol(rpc)]
    #[derive(Debug, Serialize, Deserialize)]
    SilentTimelockEncryptionBlueprint,
    "contracts/out/SilentTimelockEncryptionBlueprint.sol/SilentTimelockEncryptionBlueprint.json",
);

#[cfg(test)]
mod e2e {
    use super::*;
    use crate::context::ServiceContext;
    use crate::decrypt::DecryptState;
    use crate::jobs::DecryptCiphertextEventHandler;
    use crate::setup::setup;
    use blueprint_sdk::alloy::primitives::Bytes;
    use api::runtime_types::bounded_collections::bounded_vec::BoundedVec;
    use api::runtime_types::tangle_primitives::services::field::Field;
    use api::services::calls::types::call::Args;
    use ark_bn254::Bn254;
    use ark_ec::pairing::Pairing;
    use ark_poly::univariate::DensePolynomial;
    use ark_std::UniformRand;
    use blueprint_sdk::alloy::network::EthereumWallet;
    use blueprint_sdk::alloy::providers::{ProviderBuilder, WsConnect};
    use blueprint_sdk::alloy::signers::local::PrivateKeySigner;
    use blueprint_sdk::contexts::keystore::KeystoreContext;
    use blueprint_sdk::contexts::tangle::TangleClient;
    use blueprint_sdk::keystore::backends::Backend;
    use blueprint_sdk::logging::{self, error, info};
    use blueprint_sdk::tangle_subxt::parity_scale_codec::Encode;
    use blueprint_sdk::tangle_subxt::tangle_testnet_runtime::api;
    use blueprint_sdk::tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_primitives::services::service::BlueprintServiceManager;
    use blueprint_sdk::testing::tempfile;
    use blueprint_sdk::testing::utils::harness::TestHarness;
    use blueprint_sdk::testing::utils::tangle::node::transactions::{
        get_next_call_id, submit_job, wait_for_completion_of_tangle_job,
    };
    use blueprint_sdk::testing::utils::tangle::TangleTestHarness;
    use color_eyre::eyre::{self, eyre};
    use gadget_crypto::sp_core::SpEcdsa;
    use silent_threshold_encryption::kzg::KZG10;

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::needless_return)]
    async fn decrypt_ciphertext() -> Result<(), eyre::Error> {
        color_eyre::install()?;
        logging::setup_log();

        const N: usize = 3;
        const T: usize = N / 2 + 1;

        logging::info!("Running BLS blueprint test");
        let tmp_dir = tempfile::TempDir::new()?;
        let harness = TangleTestHarness::setup(tmp_dir).await?;

        // Setup service
        let (mut test_env, service_id, blueprint_id) = harness.setup_services::<N>(false).await?;
        test_env.initialize().await?;

        // Setup the parameters for testing
        let max_degree = 1 << 10;
        let tau = <Bn254 as Pairing>::ScalarField::rand(&mut ark_std::test_rng());
        let params = KZG10::<Bn254, DensePolynomial<<Bn254 as Pairing>::ScalarField>>::setup(
            max_degree, tau,
        )
        .unwrap();

        // Generate keypairs for each party
        let mut keypairs = Vec::new();
        for i in 0..N {
            let keypair =
                setup::<Bn254>(N as u32, i as u32, &params).expect("Failed to generate keypair");
            keypairs.push(keypair);
        }

        let tangle_client = TangleClient::new(harness.env().clone()).await?;
        let blueprint_address = api::storage().services().blueprints(blueprint_id);
        let blueprint = tangle_client
            .storage()
            .at_latest()
            .await?
            .fetch(&blueprint_address)
            .await?;

        let (_, blueprint) = match blueprint {
            Some((owner, blueprint)) => (owner, blueprint),
            None => return Err(eyre!("Blueprint not found")),
        };

        let blueprint_manager_address = match blueprint.manager {
            BlueprintServiceManager::Evm(contract_address) => contract_address.0.into(),
        };

        let handles = test_env.node_handles().await;
        let binding = handles.clone();
        let first_signer = binding[0].signer();
        for handle in &handles {
            let config = handle.gadget_config().await;
            let blueprint_ctx =
                ServiceContext::new(config.clone(), params.clone(), service_id).await?;

            let keygen_job =
                DecryptCiphertextEventHandler::new(&config, blueprint_ctx.clone()).await?;
            handle.add_job(keygen_job).await;
        }

        for (index, keypair) in keypairs.iter().enumerate() {
            let public_key = handles[index]
                .clone()
                .gadget_config()
                .await
                .keystore()
                .first_local::<SpEcdsa>()?;
            let secret_key = handles[index]
                .gadget_config()
                .await
                .keystore()
                .get_secret::<SpEcdsa>(&public_key)?;
            let signer = PrivateKeySigner::from_slice(&secret_key.seed())?;
            println!("Registering public key for operator {}", signer.address());
            let wallet = EthereumWallet::new(signer);
            let provider = ProviderBuilder::new()
                .with_recommended_fillers()
                .wallet(wallet)
                .on_ws(WsConnect::new(harness.ws_endpoint.clone()))
                .await
                .unwrap();
            // Register the STE public keys for each operator with the contract
            let contract =
                SilentTimelockEncryptionBlueprint::new(blueprint_manager_address, provider);

            let registered_operators = contract.getOperatorsOfService(service_id).call().await;
            println!("Registered operators: {:?}", registered_operators);

            // Submit the public key
            contract
                .registerSTEPublicKey(
                    service_id,
                    Bytes::copy_from_slice(keypair.public_key.as_ref()),
                )
                .send()
                .await
                .expect("Failed to register STE public key")
                .get_receipt()
                .await
                .expect("Failed to get receipt");
        }

        let call_id = get_next_call_id(&tangle_client)
            .await
            .expect("Failed to get next job id")
            .saturating_sub(1);

        info!("Submitting job with params service ID: {service_id}, call ID: {call_id}");

        // Create a mock ciphertext for testing
        let ciphertext = vec![0u8; 32]; // Mock ciphertext
        let threshold = Field::Uint16(T as u16);
        let mut ciphertext_bytes = Vec::new();
        for i in 0..32 {
            ciphertext_bytes.push(Field::Uint8(ciphertext[i]));
        }
        let ciphertext_field = Field::List(BoundedVec(ciphertext_bytes));
        let job_args = Args::from([threshold, ciphertext_field]);

        let call_id = get_next_call_id(&tangle_client)
            .await
            .expect("Failed to get next job id")
            .saturating_sub(1);
        // Submit the decryption job
        if let Err(err) = submit_job(
            &tangle_client,
            first_signer,
            service_id,
            0, // DECRYPT_CIPHERTEXT_JOB_ID
            job_args,
            call_id,
        )
        .await
        {
            error!("Failed to submit job: {err}");
            panic!("Failed to submit job: {err}");
        }

        // Wait for job completion
        let job_results = wait_for_completion_of_tangle_job(&tangle_client, service_id, call_id, T)
            .await
            .expect("Failed to wait for job completion");

        // Verify results
        assert_eq!(job_results.service_id, service_id);
        assert_eq!(job_results.call_id, call_id);

        // Deserialize the decryption state
        let decrypt_state: DecryptState = serde_json::from_slice(&job_results.result.encode())
            .expect("Failed to deserialize decrypt state");

        // Verify we have enough partial decryptions
        assert!(decrypt_state.partial_decryptions.len() >= T);

        // Verify we have a decryption result
        assert!(decrypt_state.decryption_result.is_some());

        Ok(())
    }
}
