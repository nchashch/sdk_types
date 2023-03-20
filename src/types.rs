pub use crate::address::*;
pub use crate::hashes::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Hash, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutPoint {
    // Created by transactions.
    Regular { txid: Txid, vout: u32 },
    // Created by block bodies.
    Coinbase { merkle_root: MerkleRoot, vout: u32 },
    // Created by mainchain deposits.
    Deposit(bitcoin::OutPoint),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Output<C> {
    Custom {
        address: Address,
        custom: C,
    },
    Regular {
        address: Address,
        value: u64,
    },
    Withdrawal {
        value: u64,
        main_fee: u64,
        side_address: Address,
        main_address: bitcoin::Address,
    },
}

impl<C> Output<C> {
    pub fn is_custom(&self) -> bool {
        matches!(self, Self::Custom { .. })
    }
    pub fn is_regular(&self) -> bool {
        matches!(self, Self::Regular { .. })
    }
    pub fn is_withdrawal(&self) -> bool {
        matches!(self, Self::Withdrawal { .. })
    }
    pub fn get_address(&self) -> Address {
        match self {
            Output::Custom { address, .. } => *address,
            Output::Regular { address, .. } => *address,
            Output::Withdrawal { side_address, .. } => *side_address,
        }
    }
}

impl<C: GetValue> GetValue for Output<C> {
    #[inline(always)]
    fn get_value(&self) -> u64 {
        match self {
            Output::Custom { custom, .. } => custom.get_value(),
            Output::Regular { value, .. } => *value,
            Output::Withdrawal { value, .. } => *value,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction<A, C> {
    pub inputs: Vec<OutPoint>,
    pub authorizations: Vec<A>,
    pub outputs: Vec<Output<C>>,
}

impl<A: Serialize, C: Serialize> Transaction<A, C> {
    pub fn txid(&self) -> Txid {
        hash(self).into()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Body<A, C> {
    pub coinbase: Vec<Output<C>>,
    pub transactions: Vec<Transaction<A, C>>,
}

impl<A: Serialize, C: Clone + GetValue + Serialize> Body<A, C> {
    pub fn new(transactions: Vec<Transaction<A, C>>, coinbase: Vec<Output<C>>) -> Self {
        Self {
            coinbase,
            transactions,
        }
    }

    pub fn compute_merkle_root(&self) -> MerkleRoot {
        // FIXME: Compute actual merkle root instead of just a hash.
        hash(&(&self.coinbase, &self.transactions)).into()
    }

    pub fn get_inputs(&self) -> Vec<OutPoint> {
        self.transactions
            .iter()
            .flat_map(|tx| tx.inputs.iter())
            .copied()
            .collect()
    }

    pub fn get_outputs(&self) -> HashMap<OutPoint, Output<C>> {
        let mut outputs = HashMap::new();
        let merkle_root = self.compute_merkle_root();
        for (vout, output) in self.coinbase.iter().enumerate() {
            let vout = vout as u32;
            let outpoint = OutPoint::Coinbase { merkle_root, vout };
            outputs.insert(outpoint, output.clone());
        }
        for transaction in &self.transactions {
            let txid = transaction.txid();
            for (vout, output) in transaction.outputs.iter().enumerate() {
                let vout = vout as u32;
                let outpoint = OutPoint::Regular { txid, vout };
                outputs.insert(outpoint, output.clone());
            }
        }
        outputs
    }

    pub fn get_coinbase_value(&self) -> u64 {
        self.coinbase.iter().map(|output| output.get_value()).sum()
    }
}

pub trait GetAddress {
    fn get_address(&self) -> Address;
}

pub trait GetValue {
    fn get_value(&self) -> u64;
}
