pub use crate::address::*;
pub use crate::hashes::*;
use crate::traits::UtxoMap;
use ed25519_dalek::{Signer, Verifier};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum OutPoint {
    Regular { txid: Txid, vout: u32 },
    Coinbase { merkle_root: MerkleRoot, vout: u32 },
    // These exist on mainchain.
    Deposit(bitcoin::OutPoint),
}

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct Authorization {
    public_key: ed25519_dalek::PublicKey,
    signature: ed25519_dalek::Signature,
}

impl Authorization {
    pub fn new(keypair: &ed25519_dalek::Keypair, txid_without_authorizations: &Txid) -> Self {
        let hash: &Hash = txid_without_authorizations.into();
        Self {
            signature: keypair.sign(hash),
            public_key: keypair.public,
        }
    }
    pub fn is_valid(&self, txid_without_authorizations: &Txid) -> bool {
        let hash: &Hash = txid_without_authorizations.into();
        self.public_key.verify(hash, &self.signature).is_ok()
    }
    pub fn get_address(&self) -> Address {
        self.public_key.into()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Output<R> {
    Regular(R),
    Withdrawal {
        value: u64,
        main_fee: u64,
        side_address: Address,
        main_address: bitcoin::Address,
    },
}

trait CustomOutput {
    fn get_address(&self) -> Address;
    fn get_value(&self) -> u64;
}

impl<R: CustomOutput> Output<R> {
    pub fn is_withdrawal(&self) -> bool {
        match self {
            Self::Withdrawal { .. } => true,
            _ => false,
        }
    }
    pub fn get_address(&self) -> Address {
        match self {
            Output::Regular(output) => output.get_address(),
            Output::Withdrawal { side_address, .. } => *side_address,
        }
    }
    pub fn get_value(&self) -> u64 {
        match self {
            Output::Regular(output) => output.get_value(),
            Output::Withdrawal { value, .. } => *value,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction<R> {
    pub inputs: Vec<OutPoint>,
    pub authorizations: Vec<Authorization>,
    pub outputs: Vec<Output<R>>,
}

impl<R: Clone + CustomOutput + Serialize + for<'de> Deserialize<'de>> Transaction<R> {
    pub fn get_fee<U: UtxoMap<OutPoint, Output<R>>>(&self, utxos: &U) -> Option<u64> {
        let spent_outputs = match utxos.get_utxos(&self.inputs) {
            Some(spent_outputs) => spent_outputs,
            None => return None,
        };
        let value_in: u64 = spent_outputs.iter().map(|i| i.get_value()).sum();
        let value_out: u64 = self.outputs.iter().map(|o| o.get_value()).sum();
        Some(value_in - value_out)
    }

    pub fn new(inputs: Vec<OutPoint>, outputs: Vec<Output<R>>) -> Self {
        Self {
            inputs,
            outputs,
            authorizations: vec![],
        }
    }

    pub fn without_authorizations(&self) -> Transaction<R> {
        Transaction {
            authorizations: vec![],
            ..self.clone()
        }
    }

    pub fn txid(&self) -> Txid {
        hash(self).into()
    }

    pub fn validate<U: UtxoMap<OutPoint, Output<R>>>(&self, utxos: &U) -> Result<(), String> {
        let spent_outputs = match utxos.get_utxos(&self.inputs) {
            Some(spent_outputs) => spent_outputs,
            None => return Err("can not get transaction inputs".into()),
        };
        let (value_in, value_out) = {
            let value_in: u64 = spent_outputs.iter().map(|i| i.get_value()).sum();
            let value_out: u64 = self.outputs.iter().map(|o| o.get_value()).sum();
            (value_in, value_out)
        };
        if value_in < value_out {
            return Err("value in < value out".into());
        }
        if utxos.any_spent(&self.inputs) {
            return Err("output is double spent".into());
        }
        if self.inputs.len() != self.authorizations.len() {
            return Err("not enough authorizations".into());
        }
        let txid_without_authorizations = self.without_authorizations().txid();
        for (spent_output, authorization) in spent_outputs.iter().zip(self.authorizations.iter()) {
            if authorization.get_address() != spent_output.get_address() {
                return Err("authorization address does not match spent output address".into());
            }
            if !authorization.is_valid(&txid_without_authorizations) {
                return Err("invalid authorization".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Body<R> {
    pub coinbase: Vec<Output<R>>,
    pub transactions: Vec<Transaction<R>>,
}

impl<R: Clone + CustomOutput + Serialize + for<'de> Deserialize<'de>> Body<R> {
    pub fn new(transactions: Vec<Transaction<R>>, coinbase: Vec<Output<R>>) -> Self {
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

    pub fn get_outputs(&self) -> HashMap<OutPoint, Output<R>> {
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

    pub fn validate<U: UtxoMap<OutPoint, Output<R>>>(&self, utxos: &U) -> bool {
        for tx in &self.transactions {
            if tx.validate(utxos).is_err() {
                return false;
            }
        }
        let fees: Option<u64> = self.transactions.iter().map(|tx| tx.get_fee(utxos)).sum();
        let fees = match fees {
            Some(fees) => fees,
            None => return false,
        };
        let coinbase_value: u64 = self.coinbase.iter().map(|output| output.get_value()).sum();
        if coinbase_value > fees {
            return false;
        }
        true
    }
}
