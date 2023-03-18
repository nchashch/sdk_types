use sha2::Digest;

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

impl From<MerkleRoot> for Hash {
    fn from(other: MerkleRoot) -> Self {
        other.0
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

impl<'a> From<&'a Txid> for &'a Hash {
    fn from(other: &'a Txid) -> Self {
        &other.0
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

pub fn hash<T: serde::Serialize>(data: &T) -> Hash {
    let mut hasher = sha2::Sha256::new();
    let data_serialized =
        bincode::serialize(data).expect("failed to serialize a type to compute a hash");
    hasher.update(data_serialized);
    hasher.finalize().into()
}
