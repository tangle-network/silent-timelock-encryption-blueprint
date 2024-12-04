use alloy_primitives::Address;
use api::services::events::JobCalled;
use ark_bn254::Bn254;
use gadget_sdk::compute_sha256_hash;
use gadget_sdk::contexts::TangleClientContext;
use gadget_sdk::network::round_based_compat::NetworkDeliveryWrapper;
use gadget_sdk::tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_primitives::services::BlueprintServiceManager;
use gadget_sdk::{self as sdk};
use sdk::event_listener::tangle::{
    jobs::{services_post_processor, services_pre_processor},
    TangleEventListener,
};
use sdk::ext::tangle_subxt::tangle_testnet_runtime::api;
use silent_threshold_encryption::encryption::Ciphertext;
use silent_threshold_encryption::setup::{AggregateKey, SecretKey};
use sp_core::ecdsa::Public;
use std::collections::BTreeMap;

use crate::context::{ServiceContext, KEYPAIR_KEY};
use crate::decrypt::{threshold_decrypt_protocol, DecryptError};
use crate::setup::from_bytes;
use crate::SilentTimelockEncryptionBlueprint;

/// Decrypts a ciphertext using the threshold decryption protocol
#[sdk::job(
    id = 0,
    params(ciphertext, threshold),
    result(_),
    event_listener(
        listener = TangleEventListener::<ServiceContext, JobCalled>,
        pre_processor = services_pre_processor,
        post_processor = services_post_processor,
    ),
)]
pub async fn decrypt_ciphertext(
    ciphertext: Vec<u8>,
    threshold: u16,
    context: ServiceContext,
) -> Result<Vec<u8>, DecryptError> {
    let blueprint_id = context
        .blueprint_id()
        .map_err(|e| DecryptError::ContextError(e.to_string()))?;
    let blueprint_address_key = api::services::storage::StorageApi.blueprints(blueprint_id);
    let blueprint_manager_address = context
        .tangle_client()
        .await
        .unwrap()
        .storage()
        .at_latest()
        .await
        .unwrap()
        .fetch(&blueprint_address_key)
        .await
        .unwrap()
        .map(|v| match v.1.manager {
            BlueprintServiceManager::Evm(address) => Address::from(address.0),
        })
        .unwrap();
    let call_id = context
        .current_call_id()
        .await
        .map_err(|e| DecryptError::ContextError(e.to_string()))?;

    // Deserialize the ciphertext
    let ciphertext: Ciphertext<Bn254> = from_bytes(&ciphertext);

    // Get the keypair from storage
    let keypair = context
        .secret_key_store
        .get(KEYPAIR_KEY)
        .ok_or(DecryptError::ContextError("Keypair not found".to_string()))?;

    // Deserialize the secret key
    let secret_key: SecretKey<Bn254> = from_bytes(&keypair.secret_key);

    // Setup party information
    let (i, operators) = context
        .get_party_index_and_operators()
        .await
        .map_err(|e| DecryptError::ContextError(e.to_string()))?;

    let parties: BTreeMap<u16, Public> = operators
        .into_iter()
        .enumerate()
        .map(|(j, (_, ecdsa))| (j as u16, ecdsa))
        .collect();

    let num_parties = parties.values().len();

    let (meta_hash, deterministic_hash) =
        compute_deterministic_hashes(num_parties as u16, blueprint_id, call_id);
    let network = NetworkDeliveryWrapper::new(
        context.network_backend.clone(),
        i as u16,
        deterministic_hash,
        parties,
    );

    let party = round_based::party::MpcParty::connected(network);
    let ws_rpc_endpoint = &context.config.ws_rpc_endpoint;
    let service_id = context.config.service_id().unwrap();
    let provider = alloy_provider::ProviderBuilder::new()
        .with_recommended_fillers()
        .on_ws(alloy_provider::WsConnect::new(ws_rpc_endpoint))
        .await
        .unwrap();
    let contract = SilentTimelockEncryptionBlueprint::new(blueprint_manager_address, provider);
    // Verify all public keys were registered correctly
    let registered_keys = contract
        .getAllSTEPublicKeys(service_id)
        .call()
        .await
        .map(|v| v._0)
        .expect("Failed to get registered public keys");
    let pk = vec![];
    let agg_key = AggregateKey::<Bn254>::new(pk, &context.params);
    // Run the decryption protocol
    let decryption = threshold_decrypt_protocol(
        party,
        i as u16,
        threshold,
        num_parties as u16,
        &secret_key,
        &ciphertext,
        &agg_key,
        &context.params,
    )
    .await?;

    // Serialize the decryption
    let decryption = serde_json::to_vec(&decryption)
        .map_err(|e| DecryptError::SerializationError(e.to_string()))?;

    Ok(decryption)
}

pub const KEYGEN_SALT: &str = "silent_timelock_encryption";
pub const META_SALT: &str = "silent";

/// Helper function to compute deterministic hashes for the keygen process
fn compute_deterministic_hashes(n: u16, blueprint_id: u64, call_id: u64) -> ([u8; 32], [u8; 32]) {
    let meta_hash = compute_sha256_hash!(
        n.to_be_bytes(),
        blueprint_id.to_be_bytes(),
        call_id.to_be_bytes(),
        META_SALT
    );

    let deterministic_hash = compute_sha256_hash!(meta_hash.as_ref(), KEYGEN_SALT);

    (meta_hash, deterministic_hash)
}
