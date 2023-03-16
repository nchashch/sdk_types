use crate::traits::{OutputStore, UtxoSet};
use bitcoin::hashes::Hash as _;
use ed25519_dalek::{Signer, Verifier};
use sha2::Digest;
use std::collections::HashMap;

pub const THIS_SIDECHAIN: usize = 0;

const SHA256_LENGTH: usize = 32;
pub type Hash = [u8; SHA256_LENGTH];

#[derive(Clone, Copy, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
pub struct BlockHash(Hash);

impl From<Hash> for BlockHash {
    fn from(other: Hash) -> Self {
        Self(other)
    }
}

impl std::fmt::Display for BlockHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl std::fmt::Debug for BlockHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
pub struct MerkleRoot(Hash);

impl From<Hash> for MerkleRoot {
    fn from(other: Hash) -> Self {
        Self(other)
    }
}

impl std::fmt::Display for MerkleRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl std::fmt::Debug for MerkleRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Txid(pub Hash);

impl From<Hash> for Txid {
    fn from(other: Hash) -> Self {
        Self(other)
    }
}

impl From<Txid> for Hash {
    fn from(other: Txid) -> Self {
        other.0
    }
}

impl std::fmt::Display for Txid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl std::fmt::Debug for Txid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Address(pub Hash);

impl Address {
    pub fn to_string(&self) -> String {
        bs58::encode(self.0)
            .with_alphabet(bs58::Alphabet::BITCOIN)
            .with_check()
            .into_string()
    }

    pub fn to_deposit_string(&self) -> String {
        format_deposit_address(THIS_SIDECHAIN, &self.to_string())
    }
}

fn format_deposit_address(sidechain_number: usize, address: &str) -> String {
    let deposit_address: String = format!("s{}_{}_", sidechain_number, address);
    let hash = sha256::digest(deposit_address.as_bytes());
    let hash: String = hash[..6].into();
    format!("{}{}", deposit_address, hash)
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl std::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl From<ed25519_dalek::PublicKey> for Address {
    fn from(other: ed25519_dalek::PublicKey) -> Self {
        Self(hash(&other.to_bytes()))
    }
}

impl std::str::FromStr for Address {
    type Err = bs58::decode::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let address = bs58::decode(s)
            .with_alphabet(bs58::Alphabet::BITCOIN)
            .with_check(None)
            .into_vec()?;
        assert_eq!(address.len(), 32);
        Ok(Address(address.try_into().unwrap()))
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
pub enum OutPoint {
    Regular { txid: Txid, vout: u32 },
    Coinbase { merkle_root: MerkleRoot, vout: u32 },
    // These exist on mainchain.
    Deposit(bitcoin::OutPoint),
}

#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Authorization {
    public_key: ed25519_dalek::PublicKey,
    signature: ed25519_dalek::Signature,
}

impl Authorization {
    pub fn new(keypair: &ed25519_dalek::Keypair, transaction: &Transaction) -> Self {
        let hash: Hash = transaction.txid().into();
        Self {
            signature: keypair.sign(&hash),
            public_key: keypair.public,
        }
    }
    pub fn is_valid(&self, txid_without_authorizations: Txid) -> bool {
        let hash: Hash = txid_without_authorizations.into();
        self.public_key.verify(&hash, &self.signature).is_ok()
    }
    pub fn get_address(&self) -> Address {
        self.public_key.into()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Output {
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

impl Output {
    pub fn is_withdrawal(&self) -> bool {
        match self {
            Self::Withdrawal { .. } => true,
            _ => false,
        }
    }
    pub fn get_address(&self) -> Address {
        match self {
            Output::Regular { address, .. } => *address,
            Output::Withdrawal { side_address, .. } => *side_address,
        }
    }
    pub fn get_value(&self) -> u64 {
        match self {
            Output::Regular { value, .. } => *value,
            Output::Withdrawal { value, .. } => *value,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Transaction {
    pub inputs: Vec<OutPoint>,
    pub authorizations: Vec<Authorization>,
    pub outputs: Vec<Output>,
}

impl Transaction {
    pub fn get_inputs<O: OutputStore<OutPoint, Output>>(&self, store: &O) -> Option<Vec<Output>> {
        self.inputs
            .iter()
            .map(|outpoint| store.get_output(outpoint).cloned())
            .collect()
    }

    pub fn get_fee<O: OutputStore<OutPoint, Output>>(&self, store: &O) -> Option<u64> {
        let inputs = match self.get_inputs(store) {
            Some(inputs) => inputs,
            None => return None,
        };
        let value_in: u64 = inputs.iter().map(|i| i.get_value()).sum();
        let value_out: u64 = self.outputs.iter().map(|o| o.get_value()).sum();
        Some(value_in - value_out)
    }

    pub fn new(inputs: Vec<OutPoint>, outputs: Vec<Output>) -> Self {
        Self {
            inputs,
            outputs,
            authorizations: vec![],
        }
    }

    pub fn without_authorizations(&self) -> Transaction {
        Transaction {
            authorizations: vec![],
            ..self.clone()
        }
    }

    pub fn txid(&self) -> Txid {
        hash(self).into()
    }

    pub fn validate<U: UtxoSet<OutPoint>, O: OutputStore<OutPoint, Output>>(
        &self,
        utxo_set: &U,
        outputs: &O,
    ) -> Result<(), String> {
        let (value_in, value_out) = {
            let inputs = match self.get_inputs(outputs) {
                Some(inputs) => inputs,
                None => return Err("can not get transaction inputs".into()),
            };
            let value_in: u64 = inputs.iter().map(|i| i.get_value()).sum();
            let value_out: u64 = self.outputs.iter().map(|o| o.get_value()).sum();
            (value_in, value_out)
        };
        if value_in < value_out {
            return Err("value in < value out".into());
        }
        let txid_without_authorizations = self.without_authorizations().txid();
        if self.inputs.len() != self.authorizations.len() {
            return Err("not enough authorizations".into());
        }
        for (outpoint, authorization) in self.inputs.iter().zip(self.authorizations.iter()) {
            if utxo_set.is_spent(outpoint) {
                return Err("output is double spent".into());
            }
            if !authorization.is_valid(txid_without_authorizations) {
                return Err("invalid authorization".into());
            }
            if let Some(spent_output) = outputs.get_output(outpoint) {
                if spent_output.get_address() != authorization.get_address() {
                    return Err("addresses don't match".into());
                }
            } else {
                return Err("output doesn't exist".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Copy, Clone, serde::Serialize, serde::Deserialize)]
pub struct Header {
    pub prev_side_block_hash: BlockHash,
    pub prev_main_block_hash: bitcoin::BlockHash,
    pub merkle_root: MerkleRoot,
}

impl Header {
    pub fn zero() -> Self {
        Self {
            prev_side_block_hash: [0; 32].into(),
            prev_main_block_hash: bitcoin::BlockHash::from_inner([0; 32]),
            merkle_root: [0; 32].into(),
        }
    }

    pub fn new(
        prev_side_block_hash: BlockHash,
        prev_main_block_hash: bitcoin::BlockHash,
        body: &Body,
    ) -> Self {
        Self {
            prev_side_block_hash,
            prev_main_block_hash,
            merkle_root: body.compute_merkle_root(),
        }
    }

    pub fn hash(&self) -> BlockHash {
        hash(self).into()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Body {
    pub coinbase: Vec<Output>,
    pub transactions: Vec<Transaction>,
}

impl Body {
    pub fn new(transactions: Vec<Transaction>, coinbase: Vec<Output>) -> Body {
        Body {
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

    pub fn get_created_outpoints(&self) -> Vec<OutPoint> {
        self.get_outputs().keys().copied().collect()
    }

    pub fn get_outputs(&self) -> HashMap<OutPoint, Output> {
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

    pub fn validate<U: UtxoSet<OutPoint>, O: OutputStore<OutPoint, Output>>(
        &self,
        utxo_set: &U,
        outputs: &O,
    ) -> bool {
        for tx in &self.transactions {
            if tx.validate(utxo_set, outputs).is_err() {
                return false;
            }
        }
        let fees: Option<u64> = self.transactions.iter().map(|tx| tx.get_fee(outputs)).sum();
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

pub fn hash<T: serde::Serialize>(data: &T) -> Hash {
    let mut hasher = sha2::Sha256::new();
    let data_serialized =
        bincode::serialize(data).expect("failed to serialize a type to compute a hash");
    hasher.update(data_serialized);
    hasher.finalize().into()
}
