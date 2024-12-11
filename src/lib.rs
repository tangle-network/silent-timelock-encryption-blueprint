use alloy_sol_types::sol;

pub mod context;
pub mod decrypt;
pub mod jobs;
pub mod setup;
pub use jobs::decrypt_ciphertext;
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
    use crate::decrypt::DecryptState;
    use crate::setup::setup;
    use alloy_primitives::Bytes;
    use api::runtime_types::bounded_collections::bounded_vec::BoundedVec;
    use api::runtime_types::tangle_primitives::services::field::Field;
    use api::runtime_types::tangle_primitives::services::BlueprintServiceManager;
    use api::services::calls::types::call::Args;
    use ark_bn254::Bn254;
    use ark_ec::pairing::Pairing;
    use ark_poly::univariate::DensePolynomial;
    use ark_std::UniformRand;
    use blueprint_test_utils::test_ext::*;
    use blueprint_test_utils::*;
    use cargo_tangle::deploy::Opts;
    use gadget_sdk::subxt_core::tx::signer::Signer;
    use gadget_sdk::tangle_subxt::parity_scale_codec::Encode;
    use gadget_sdk::tangle_subxt::tangle_testnet_runtime::api;
    use gadget_sdk::{error, info};
    use silent_threshold_encryption::kzg::{PowersOfTau, KZG10};
    use tangle::NodeConfig;

    pub fn setup_testing_log() {
        use tracing_subscriber::util::SubscriberInitExt;
        let env_filter = tracing_subscriber::EnvFilter::from_default_env();
        let _ = tracing_subscriber::fmt::SubscriberBuilder::default()
            .without_time()
            .with_target(true)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::NONE)
            .with_env_filter(env_filter)
            .with_test_writer()
            .finish()
            .try_init();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::needless_return)]
    async fn decrypt_ciphertext() {
        setup_testing_log();

        const N: usize = 3;
        const T: usize = N / 2 + 1;
        let node_config = NodeConfig::new(false);
        new_test_ext_blueprint_manager::<N, 1, _, _, _>(
            "",
            run_test_blueprint_manager,
            node_config,
        )
        .await
        .execute_with_async(move |client, handles, svcs, opts| async move {
            let keypair = handles[0].sr25519_id().clone();
            let blueprint_manager_address = match svcs.blueprint.manager {
                BlueprintServiceManager::Evm(contract_address) => contract_address.0.into(),
            };

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
                let keypair = setup::<Bn254>(N as u32, i as u32, &params)
                    .expect("Failed to generate keypair");
                keypairs.push(keypair);
            }

            let service = svcs.services.last().unwrap();
            let service_id = service.id;

            for (index, keypair) in keypairs.iter().enumerate() {
                let signer = handles[index].ecdsa_id().alloy_key().unwrap();
                let wallet = alloy_network::EthereumWallet::from(signer);
                let provider = alloy_provider::ProviderBuilder::new()
                    .with_recommended_fillers()
                    .wallet(wallet)
                    .on_ws(alloy_provider::WsConnect::new(opts.ws_rpc_url.clone()))
                    .await
                    .unwrap();
                // Register the STE public keys for each operator with the contract
                let contract =
                    SilentTimelockEncryptionBlueprint::new(blueprint_manager_address, provider);

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

            let provider = alloy_provider::ProviderBuilder::new()
                .with_recommended_fillers()
                .on_ws(alloy_provider::WsConnect::new(opts.ws_rpc_url.clone()))
                .await
                .unwrap();
            let contract =
                SilentTimelockEncryptionBlueprint::new(blueprint_manager_address, provider);
            // Verify all public keys were registered correctly
            let registered_keys = contract
                .getAllSTEPublicKeys(service_id)
                .call()
                .await
                .map(|v| v._0)
                .expect("Failed to get registered public keys");

            assert_eq!(
                registered_keys.len(),
                N,
                "Not all public keys were registered"
            );

            for (i, registered_key) in registered_keys.iter().enumerate() {
                assert_eq!(
                    registered_key.as_ref(),
                    keypairs[i].public_key.as_slice(),
                    "Public key mismatch for operator {}",
                    i
                );
            }

            let call_id = get_next_call_id(client)
                .await
                .expect("Failed to get next job id")
                .saturating_sub(1);

            info!("Submitting job with params service ID: {service_id}, call ID: {call_id}");

            // Create a mock ciphertext for testing
            let ciphertext = vec![0u8; 32]; // Mock ciphertext
            let threshold = Field::Uint16(T as u16);
            let ciphertext_field = Field::Bytes(BoundedVec(ciphertext));
            let job_args = Args::from([ciphertext_field, threshold]);

            let call_id = get_next_call_id(client)
                .await
                .expect("Failed to get next job id")
                .saturating_sub(1);
            // Submit the decryption job
            if let Err(err) = submit_job(
                client, &keypair, service_id, 0, // DECRYPT_CIPHERTEXT_JOB_ID
                job_args, call_id,
            )
            .await
            {
                error!("Failed to submit job: {err}");
                panic!("Failed to submit job: {err}");
            }

            // Wait for job completion
            let job_results = wait_for_completion_of_tangle_job(client, service_id, call_id, T)
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

            // If we're party 0, verify we have a decryption result
            if handles[0].sr25519_id().account_id() == keypair.account_id() {
                assert!(decrypt_state.decryption_result.is_some());
            }
        })
        .await;
    }
}
