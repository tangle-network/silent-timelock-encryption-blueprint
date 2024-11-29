use crate::decrypt::DecryptState;
use ark_bn254::Bn254;
use color_eyre::eyre;
use gadget_sdk::subxt_core::tx::signer::Signer;
use gadget_sdk::subxt_core::utils::AccountId32;
use gadget_sdk::{
    self as sdk,
    ctx::{KeystoreContext, ServicesContext, TangleClientContext},
    network::NetworkMultiplexer,
    store::LocalDatabase,
    subxt_core::ext::sp_core::ecdsa,
};
use sdk::tangle_subxt::tangle_testnet_runtime::api;
use silent_threshold_encryption::kzg::PowersOfTau;
use sp_core::ecdsa::Public;
use std::collections::BTreeMap;

use std::{path::PathBuf, sync::Arc};

use crate::setup::SilentThresholdEncryptionKeypair;

#[derive(Clone, ServicesContext, TangleClientContext, KeystoreContext)]
pub struct ServiceContext {
    #[config]
    pub config: sdk::config::StdGadgetConfiguration,
    pub network_backend: Arc<NetworkMultiplexer>,
    pub secret_key_store: Arc<LocalDatabase<SilentThresholdEncryptionKeypair>>,
    pub decrypt_state_store: Arc<LocalDatabase<DecryptState>>,
    pub identity: ecdsa::Pair,
    pub params: PowersOfTau<Bn254>,
}

pub const NETWORK_PROTOCOL: &str = "/silent-timelock-encryption.bn254";
pub const KEYPAIR_KEY: &str = "silent_timelock_encryption_keypair";

impl ServiceContext {
    pub fn new(
        config: sdk::config::StdGadgetConfiguration,
        params: PowersOfTau<Bn254>,
    ) -> eyre::Result<Self> {
        let network_config = config
            .libp2p_network_config(NETWORK_PROTOCOL)
            .map_err(|err| eyre::eyre!("Failed to create network configuration: {err}"))?;

        let identity = network_config.ecdsa_key.clone();
        let gossip_handle = sdk::network::setup::start_p2p_network(network_config)
            .map_err(|err| eyre::eyre!("Failed to start the P2P network: {err}"))?;

        let secret_keystore_dir = PathBuf::from(config.keystore_uri.clone()).join("secret.json");
        let decrypt_store = PathBuf::from(config.keystore_uri.clone()).join("decrypt.json");
        let secret_key_store = Arc::new(LocalDatabase::open(secret_keystore_dir));
        let decrypt_state_store = Arc::new(LocalDatabase::open(decrypt_store));

        Ok(Self {
            params,
            secret_key_store: secret_key_store,
            decrypt_state_store: decrypt_state_store,
            identity,
            config,
            network_backend: Arc::new(NetworkMultiplexer::new(gossip_handle)),
        })
    }

    /// Returns a reference to the configuration
    #[inline]
    pub fn config(&self) -> &sdk::config::StdGadgetConfiguration {
        &self.config
    }

    /// Returns a clone of the store handle for secret key
    #[inline]
    pub fn secret_key_store(&self) -> Arc<LocalDatabase<SilentThresholdEncryptionKeypair>> {
        self.secret_key_store.clone()
    }

    /// Returns a clone of the store handle for decrypt state
    #[inline]
    pub fn decrypt_state_store(&self) -> Arc<LocalDatabase<DecryptState>> {
        self.decrypt_state_store.clone()
    }

    /// Returns the network protocol version
    #[inline]
    pub fn network_protocol(&self) -> &str {
        NETWORK_PROTOCOL
    }
}

// Protocol-specific implementations
impl ServiceContext {
    /// Retrieves the current blueprint ID from the configuration
    ///
    /// # Errors
    /// Returns an error if the blueprint ID is not found in the configuration
    pub fn blueprint_id(&self) -> eyre::Result<u64> {
        self.config()
            .protocol_specific
            .tangle()
            .map(|c| c.blueprint_id)
            .map_err(|err| eyre::eyre!("Blueprint ID not found in configuration: {err}"))
    }

    /// Retrieves the current party index and operator mapping
    ///
    /// # Errors
    /// Returns an error if:
    /// - Failed to retrieve operator keys
    /// - Current party is not found in the operator list
    pub async fn get_party_index_and_operators(
        &self,
    ) -> eyre::Result<(usize, BTreeMap<AccountId32, Public>)> {
        let parties = self.current_service_operators_ecdsa_keys().await?;
        let my_id = self.config.first_sr25519_signer()?.account_id();

        gadget_sdk::trace!(
            "Looking for {my_id:?} in parties: {:?}",
            parties.keys().collect::<Vec<_>>()
        );

        let index_of_my_id = parties
            .iter()
            .position(|(id, _)| id == &my_id)
            .ok_or_else(|| eyre::eyre!("Party not found in operator list"))?;

        Ok((index_of_my_id, parties))
    }

    /// Retrieves the ECDSA keys for all current service operators
    ///
    /// # Errors
    /// Returns an error if:
    /// - Failed to connect to the Tangle client
    /// - Failed to retrieve operator information
    /// - Missing ECDSA key for any operator
    pub async fn current_service_operators_ecdsa_keys(
        &self,
    ) -> eyre::Result<BTreeMap<AccountId32, ecdsa::Public>> {
        let client = self.tangle_client().await?;
        let current_blueprint = self.blueprint_id()?;
        let current_service_op = self.current_service_operators(&client).await?;
        let storage = client.storage().at_latest().await?;

        let mut map = BTreeMap::new();
        for (operator, _) in current_service_op {
            let addr = api::storage()
                .services()
                .operators(current_blueprint, &operator);

            let maybe_pref = storage.fetch(&addr).await.map_err(|err| {
                eyre::eyre!("Failed to fetch operator storage for {operator}: {err}")
            })?;

            if let Some(pref) = maybe_pref {
                map.insert(operator, ecdsa::Public(pref.key));
            } else {
                return Err(eyre::eyre!("Missing ECDSA key for operator {operator}"));
            }
        }

        Ok(map)
    }

    /// Retrieves the current call ID for this job
    ///
    /// # Errors
    /// Returns an error if failed to retrieve the call ID from storage
    pub async fn current_call_id(&self) -> eyre::Result<u64> {
        let client = self.tangle_client().await?;
        let addr = api::storage().services().next_job_call_id();
        let storage = client.storage().at_latest().await?;

        let maybe_call_id = storage
            .fetch_or_default(&addr)
            .await
            .map_err(|err| eyre::eyre!("Failed to fetch current call ID: {err}"))?;

        Ok(maybe_call_id.saturating_sub(1))
    }
}
