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
    params(threshold, ciphertext),
    result(_),
    event_listener(
        listener = TangleEventListener::<ServiceContext, JobCalled>,
        pre_processor = services_pre_processor,
        post_processor = services_post_processor,
    ),
)]
pub async fn decrypt_ciphertext(
    threshold: u16,
    ciphertext: Vec<u8>,
    context: ServiceContext,
) -> Result<Vec<u8>, DecryptError> {
    println!("Starting decrypt_ciphertext job");
    let blueprint_id = match context.blueprint_id() {
        Ok(id) => {
            println!("Got blueprint ID: {}", id);
            id
        }
        Err(e) => {
            gadget_sdk::error!("Failed to get blueprint ID: {}", e);
            return Err(DecryptError::ContextError(e.to_string()));
        }
    };

    let blueprint_address_key = api::services::storage::StorageApi.blueprints(blueprint_id);
    println!("Fetching blueprint manager address from storage");
    let blueprint_manager_address = match context
        .tangle_client()
        .await
        .map_err(|e| {
            gadget_sdk::error!("Failed to get tangle client: {}", e);
            DecryptError::ContextError(e.to_string())
        })?
        .storage()
        .at_latest()
        .await
        .map_err(|e| {
            gadget_sdk::error!("Failed to get latest storage: {}", e);
            DecryptError::ContextError(e.to_string())
        })?
        .fetch(&blueprint_address_key)
        .await
        .map_err(|e| {
            gadget_sdk::error!("Failed to fetch from storage: {}", e);
            DecryptError::ContextError(e.to_string())
        })? {
        Some((_, v)) => {
            let addr = match v.manager {
                BlueprintServiceManager::Evm(address) => Address::from(address.0),
            };
            println!("Got blueprint manager address: {:?}", addr);
            addr
        }
        None => {
            gadget_sdk::error!("Blueprint manager address not found in storage");
            return Err(DecryptError::ContextError(
                "Blueprint manager address not found".to_string(),
            ));
        }
    };

    let call_id = match context.current_call_id().await {
        Ok(id) => {
            println!("Got call ID: {}", id);
            id
        }
        Err(e) => {
            gadget_sdk::error!("Failed to get call ID: {}", e);
            return Err(DecryptError::ContextError(e.to_string()));
        }
    };

    println!("Deserializing ciphertext");
    let ciphertext: Ciphertext<Bn254> = from_bytes(&ciphertext);

    println!("Getting keypair from storage");
    let keypair = match context.secret_key_store.get(KEYPAIR_KEY) {
        Some(k) => k,
        None => {
            gadget_sdk::error!("Keypair not found in storage");
            return Err(DecryptError::ContextError("Keypair not found".to_string()));
        }
    };

    println!("Deserializing secret key");
    let secret_key: SecretKey<Bn254> = from_bytes(&keypair.secret_key);

    println!("Getting party information");
    let (i, operators) = match context.get_party_index_and_operators().await {
        Ok((idx, ops)) => {
            println!("Got party index {} and {} operators", idx, ops.len());
            (idx, ops)
        }
        Err(e) => {
            gadget_sdk::error!("Failed to get party info: {}", e);
            return Err(DecryptError::ContextError(e.to_string()));
        }
    };

    let parties: BTreeMap<u16, Public> = operators
        .into_iter()
        .enumerate()
        .map(|(j, (_, ecdsa))| (j as u16, ecdsa))
        .collect();

    let num_parties = parties.values().len();
    println!("Setting up network with {} parties", num_parties);

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

    println!("Setting up provider and contract");
    let provider = match alloy_provider::ProviderBuilder::new()
        .with_recommended_fillers()
        .on_ws(alloy_provider::WsConnect::new(ws_rpc_endpoint))
        .await
    {
        Ok(p) => p,
        Err(e) => {
            gadget_sdk::error!("Failed to create provider: {}", e);
            return Err(DecryptError::ContextError(format!(
                "Failed to create provider: {}",
                e
            )));
        }
    };

    let contract = SilentTimelockEncryptionBlueprint::new(blueprint_manager_address, provider);

    println!("Getting registered STE public keys");
    let registered_keys = match contract.getAllSTEPublicKeys(service_id).call().await {
        Ok(v) => v._0,
        Err(e) => {
            gadget_sdk::error!("Failed to get registered public keys: {}", e);
            return Err(DecryptError::ContextError(format!(
                "Failed to get registered public keys: {}",
                e
            )));
        }
    };

    let pk = vec![];
    let agg_key = AggregateKey::<Bn254>::new(pk, &context.params);

    println!("Running decryption protocol");
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

    println!("Serializing decryption result");
    let decryption = match serde_json::to_vec(&decryption) {
        Ok(d) => d,
        Err(e) => {
            gadget_sdk::error!("Failed to serialize decryption: {}", e);
            return Err(DecryptError::SerializationError(e.to_string()));
        }
    };

    println!("Decrypt ciphertext job completed successfully");
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
