use ed25519_dalek::{Signer, Verifier};
use sha2::Digest;

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
