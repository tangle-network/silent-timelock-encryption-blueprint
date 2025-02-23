use crate::decrypt::Msg;
use crate::SilentTimelockEncryptionBlueprint;
use api::services::events::JobCalled;
use ark_bn254::Bn254;
use blueprint_sdk::alloy::primitives::Address;
use blueprint_sdk::alloy::providers::{ProviderBuilder, WsConnect};
use blueprint_sdk::event_listeners::tangle::events::TangleEventListener;
use blueprint_sdk::event_listeners::tangle::services::{services_post_processor, services_pre_processor};
use blueprint_sdk::tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_primitives::services::service::BlueprintServiceManager;
use blueprint_sdk as sdk;
use blueprint_sdk::networking::round_based_compat::RoundBasedNetworkAdapter;
use blueprint_sdk::networking::InstanceMsgPublicKey;
use color_eyre::Result;
use round_based::PartyIndex;
use sdk::contexts::tangle::TangleClientContext;
use sdk::logging;
use sdk::tangle_subxt::tangle_testnet_runtime::api;
use silent_threshold_encryption::encryption::Ciphertext;
use silent_threshold_encryption::setup::{AggregateKey, SecretKey};
use std::collections::HashMap;

use crate::context::{ServiceContext, KEYPAIR_KEY};
use crate::decrypt::{threshold_decrypt_protocol, DecryptError};
use crate::setup::from_bytes;

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
            blueprint_sdk::logging::error!("Failed to get blueprint ID: {}", e);
            return Err(DecryptError::ContextError(e.to_string()));
        }
    };

    let blueprint_address_key = api::services::storage::StorageApi.blueprints(blueprint_id);
    println!("Fetching blueprint manager address from storage");
    let blueprint_manager_address = match context
        .tangle_client()
        .await
        .map_err(|e| {
            blueprint_sdk::logging::error!("Failed to get tangle client: {}", e);
            DecryptError::ContextError(e.to_string())
        })?
        .storage()
        .at_latest()
        .await
        .map_err(|e| {
            blueprint_sdk::logging::error!("Failed to get latest storage: {}", e);
            DecryptError::ContextError(e.to_string())
        })?
        .fetch(&blueprint_address_key)
        .await
        .map_err(|e| {
            blueprint_sdk::logging::error!("Failed to fetch from storage: {}", e);
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
            blueprint_sdk::logging::error!("Blueprint manager address not found in storage");
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
            blueprint_sdk::logging::error!("Failed to get call ID: {}", e);
            return Err(DecryptError::ContextError(e.to_string()));
        }
    };

    println!("Deserializing ciphertext");
    let ciphertext: Ciphertext<Bn254> = from_bytes(&ciphertext);

    println!("Getting keypair from storage");
    let keypair = match context.secret_key_store.get(KEYPAIR_KEY) {
        Some(k) => k,
        None => {
            blueprint_sdk::logging::error!("Keypair not found in storage");
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
            blueprint_sdk::logging::error!("Failed to get party info: {}", e);
            return Err(DecryptError::ContextError(e.to_string()));
        }
    };

    let parties: HashMap<u16, InstanceMsgPublicKey> = operators
        .into_iter()
        .enumerate()
        .map(|(j, (_, ecdsa))| (j as PartyIndex, InstanceMsgPublicKey(ecdsa)))
        .collect();

    let n = parties.len() as u16;
    let i = i as u16;

    logging::info!("Starting Partial Threshold Decryption for party {i}, n={n}");

    let network = RoundBasedNetworkAdapter::<Msg>::new(
        context.network_handle,
        i,
        parties.clone(),
        crate::context::NETWORK_PROTOCOL,
    );

    let party = round_based::party::MpcParty::connected(network);
    let ws_rpc_endpoint = &context.config.ws_rpc_endpoint;
    let service_id = context.service_id;

    println!("Setting up provider and contract");
    let provider = match ProviderBuilder::new()
        .with_recommended_fillers()
        .on_ws(WsConnect::new(ws_rpc_endpoint))
        .await
    {
        Ok(p) => p,
        Err(e) => {
            blueprint_sdk::logging::error!("Failed to create provider: {}", e);
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
            blueprint_sdk::logging::error!("Failed to get registered public keys: {}", e);
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
        i,
        threshold,
        n,
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
            blueprint_sdk::logging::error!("Failed to serialize decryption: {}", e);
            return Err(DecryptError::SerializationError(e.to_string()));
        }
    };

    println!("Decrypt ciphertext job completed successfully");
    Ok(decryption)
}
