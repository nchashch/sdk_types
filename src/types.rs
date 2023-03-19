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

pub trait GetValue {
    fn get_value(&self) -> u64;
}

impl<C> Output<C> {
    pub fn is_withdrawal(&self) -> bool {
        matches!(self, Self::Withdrawal { .. })
    }
    pub fn is_regular(&self) -> bool {
        matches!(self, Self::Regular { .. })
    }
    pub fn is_custom(&self) -> bool {
        matches!(self, Self::Custom { .. })
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
    fn get_value(&self) -> u64 {
        match self {
            Output::Custom { custom, .. } => custom.get_value(),
            Output::Regular { value, .. } => *value,
            Output::Withdrawal { value, .. } => *value,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction<C> {
    pub inputs: Vec<OutPoint>,
    pub authorizations: Vec<Authorization>,
    pub outputs: Vec<Output<C>>,
}

impl<C: Clone + GetValue + Serialize + for<'de> Deserialize<'de>> Transaction<C> {
    pub fn get_fee<U: UtxoMap<OutPoint, Output<C>>>(&self, utxos: &U) -> Option<u64> {
        let mut spent_utxos = vec![];
        for utxo in utxos.get_utxos(&self.inputs) {
            match utxo {
                Some(utxo) => spent_utxos.push(utxo),
                None => return None,
            };
        }
        let value_in: u64 = spent_utxos.iter().map(|i| i.get_value()).sum();
        let value_out: u64 = self.outputs.iter().map(|o| o.get_value()).sum();
        Some(value_in - value_out)
    }

    pub fn new(inputs: Vec<OutPoint>, outputs: Vec<Output<C>>) -> Self {
        Self {
            inputs,
            outputs,
            authorizations: vec![],
        }
    }

    pub fn without_authorizations(&self) -> Transaction<C> {
        Transaction {
            authorizations: vec![],
            ..self.clone()
        }
    }

    pub fn txid(&self) -> Txid {
        hash(self).into()
    }

    pub fn is_authorized(&self, spent_utxos: &[Output<C>]) -> Result<(), String> {
        if self.inputs.len() != self.authorizations.len() {
            return Err("not enough authorizations".into());
        }
        let txid_without_authorizations = self.without_authorizations().txid();
        for (spent_utxo, authorization) in spent_utxos.iter().zip(self.authorizations.iter()) {
            if authorization.get_address() != spent_utxo.get_address() {
                return Err("authorization address does not match spent utxo address".into());
            }
            if !authorization.is_valid(&txid_without_authorizations) {
                return Err("invalid authorization".into());
            }
        }
        Ok(())
    }

    pub fn is_value_valid(&self, spent_utxos: &[Output<C>]) -> Result<(), String> {
        let (value_in, value_out) = {
            let value_in: u64 = spent_utxos.iter().map(|i| i.get_value()).sum();
            let value_out: u64 = self.outputs.iter().map(|o| o.get_value()).sum();
            (value_in, value_out)
        };
        if value_in < value_out {
            return Err("value in < value out".into());
        }
        Ok(())
    }

    pub fn validate<U: UtxoMap<OutPoint, Output<C>>>(&self, utxos: &U) -> Result<(), String> {
        let mut spent_utxos = vec![];
        for utxo in utxos.get_utxos(&self.inputs) {
            match utxo {
                Some(utxo) => spent_utxos.push(utxo),
                None => return Err("utxo is double spent".into()),
            };
        }
        self.is_authorized(&spent_utxos)?;
        self.is_value_valid(&spent_utxos)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Body<C> {
    pub coinbase: Vec<Output<C>>,
    pub transactions: Vec<Transaction<C>>,
}

impl<C: Clone + GetValue + Serialize + for<'de> Deserialize<'de>> Body<C> {
    pub fn new(transactions: Vec<Transaction<C>>, coinbase: Vec<Output<C>>) -> Self {
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

    pub fn validate<U: UtxoMap<OutPoint, Output<C>>>(&self, utxos: &U) -> bool {
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

struct AuthorizationsBatch {
    txids: Vec<Txid>,
    authorization_numbers: Vec<usize>,
    authorizations: Vec<Authorization>,
}

impl AuthorizationsBatch {
    pub fn verify(self) -> Result<(), ed25519_dalek::SignatureError> {
        let unrolled_txids: Vec<&[u8]> = self
            .txids
            .iter()
            .zip(self.authorization_numbers.iter())
            .flat_map(|(txid, number)| std::iter::repeat(txid.as_slice()).take(*number))
            .collect();
        let mut signatures = Vec::with_capacity(self.authorizations.len());
        let mut public_keys = Vec::with_capacity(self.authorizations.len());
        for Authorization {
            signature,
            public_key,
        } in self.authorizations.into_iter()
        {
            signatures.push(signature);
            public_keys.push(public_key);
        }
        ed25519_dalek::verify_batch(
            unrolled_txids.as_slice(),
            signatures.as_slice(),
            public_keys.as_slice(),
        )
    }
}
