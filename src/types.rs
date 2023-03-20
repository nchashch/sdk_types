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

impl std::fmt::Display for OutPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Regular { txid, vout } => write!(f, "regular {txid} {vout}"),
            Self::Coinbase { merkle_root, vout } => write!(f, "coinbase {merkle_root} {vout}"),
            Self::Deposit(bitcoin::OutPoint { txid, vout }) => write!(f, "deposit {txid} {vout}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Output<C> {
    pub address: Address,
    pub content: Content<C>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Content<C> {
    Custom(C),
    Value(u64),
    Withdrawal {
        value: u64,
        main_fee: u64,
        main_address: bitcoin::Address,
    },
}

impl<C> Content<C> {
    pub fn is_custom(&self) -> bool {
        matches!(self, Self::Custom(_))
    }
    pub fn is_regular(&self) -> bool {
        matches!(self, Self::Value(_))
    }
    pub fn is_withdrawal(&self) -> bool {
        matches!(self, Self::Withdrawal { .. })
    }
}

impl<C> GetAddress for Output<C> {
    #[inline(always)]
    fn get_address(&self) -> Address {
        self.address
    }
}

impl<C: GetValue> GetValue for Output<C> {
    #[inline(always)]
    fn get_value(&self) -> u64 {
        self.content.get_value()
    }
}

impl<C: GetValue> GetValue for Content<C> {
    #[inline(always)]
    fn get_value(&self) -> u64 {
        match self {
            Self::Custom(custom) => custom.get_value(),
            Self::Value(value) => *value,
            Self::Withdrawal { value, .. } => *value,
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
