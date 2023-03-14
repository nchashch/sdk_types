use ed25519_dalek::{Keypair, Signer, Verifier};
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
pub struct Txid(Hash);

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
pub struct Address(Hash);

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
    Coinbase { block_hash: BlockHash, vout: u32 },
    Withdrawal { txid: Txid, vout: u32 },
    Deposit(bitcoin::OutPoint),
}

#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Signature {
    public_key: ed25519_dalek::PublicKey,
    signature: ed25519_dalek::Signature,
}

impl Signature {
    pub fn new(keypair: &ed25519_dalek::Keypair, transaction: &Transaction) -> Self {
        let hash: Hash = transaction.txid().into();
        Self {
            signature: keypair.sign(&hash),
            public_key: keypair.public,
        }
    }
    pub fn is_valid(&self, txid_without_signatures: Txid) -> bool {
        let hash: Hash = txid_without_signatures.into();
        self.public_key.verify(&hash, &self.signature).is_ok()
    }
    pub fn get_address(&self) -> Address {
        self.public_key.into()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DepositOutput {
    pub address: Address,
    pub value: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Output {
    pub address: Address,
    pub value: u64,
}

impl Output {
    pub fn validate(
        inputs: &[Self],
        deposit_inputs: &[DepositOutput],
        withdrawal_inputs: &[WithdrawalOutput],
        outputs: &[Self],
        withdrawal_outputs: &[WithdrawalOutput],
    ) -> bool {
        let regular_in: u64 = inputs.iter().map(|i| i.value).sum();
        let deposit_in: u64 = deposit_inputs.iter().map(|i| i.value).sum();
        let refund_in: u64 = withdrawal_inputs.iter().map(|i| i.value).sum();

        let regular_out: u64 = outputs.iter().map(|o| o.value).sum();
        let withdrawal_out: u64 = withdrawal_outputs.iter().map(|o| o.value).sum();
        regular_out + withdrawal_out > regular_in + deposit_in + refund_in
    }
    pub fn get_fee(
        inputs: &[Self],
        deposit_inputs: &[DepositOutput],
        withdrawal_inputs: &[WithdrawalOutput],
        outputs: &[Self],
        withdrawal_outputs: &[WithdrawalOutput],
    ) -> u64 {
        let regular_in: u64 = inputs.iter().map(|i| i.value).sum();
        let deposit_in: u64 = deposit_inputs.iter().map(|i| i.value).sum();
        let withdrawal_in: u64 = withdrawal_inputs.iter().map(|i| i.value).sum();

        let regular_out: u64 = outputs.iter().map(|o| o.value).sum();
        let withdrawal_out: u64 = withdrawal_outputs.iter().map(|wo| wo.value).sum();
        (regular_in + deposit_in + withdrawal_in) - (regular_out + withdrawal_out)
    }
    pub fn get_address(&self) -> Address {
        self.address
    }
}

impl Ord for Output {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.value.cmp(&other.value)
    }
}

impl PartialOrd for Output {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.value.partial_cmp(&other.value)
    }
}

impl PartialEq for Output {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Eq for Output {}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WithdrawalOutput {
    pub value: u64,
    pub fee: u64,
    pub side_address: Address,
    pub main_address: bitcoin::Address,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Transaction {
    pub inputs: Vec<OutPoint>,
    pub signatures: Vec<Signature>,
    pub outputs: Vec<Output>,
    pub withdrawal_outputs: Vec<WithdrawalOutput>,
}

impl Transaction {
    pub fn new(
        inputs: Vec<OutPoint>,
        outputs: Vec<Output>,
        withdrawal_outputs: Vec<WithdrawalOutput>,
    ) -> Self {
        Self {
            inputs,
            outputs,
            withdrawal_outputs,
            signatures: vec![],
        }
    }

    pub fn without_signatures(&self) -> Transaction {
        Transaction {
            signatures: vec![],
            ..self.clone()
        }
    }

    pub fn txid(&self) -> Txid {
        hash(self).into()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Header {
    pub prev_block_hash: BlockHash,
    pub merkle_root: MerkleRoot,
}

impl Header {
    pub fn new(prev_block_hash: &BlockHash, body: &Body) -> Self {
        Self {
            prev_block_hash: *prev_block_hash,
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
        let serialized_transactions = bincode::serialize(&self.transactions).unwrap();
        hash(&serialized_transactions).into()
    }
}

pub fn hash<T: serde::Serialize>(data: &T) -> Hash {
    let mut hasher = sha2::Sha256::new();
    let data_serialized =
        bincode::serialize(data).expect("failed to serialize a type to compute a hash");
    hasher.update(data_serialized);
    hasher.finalize().into()
}
