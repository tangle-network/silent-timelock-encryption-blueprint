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
