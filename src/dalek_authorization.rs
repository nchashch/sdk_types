use crate::address::Address;
use crate::hashes::hash;
use crate::types::{GetAddress, Transaction};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authorization {
    pub public_key: ed25519_dalek::PublicKey,
    pub signature: ed25519_dalek::Signature,
}

impl GetAddress for Authorization {
    fn get_address(&self) -> Address {
        Address::from(hash(&self.public_key.to_bytes()))
    }
}

pub fn verify_signatures<C: Clone + Serialize>(
    transactions: &[Transaction<Authorization, C>],
) -> Result<(), ed25519_dalek::SignatureError> {
    let capacity: usize = transactions
        .iter()
        .map(|transaction| transaction.authorizations.len())
        .sum();

    let mut messages = Vec::with_capacity(capacity);
    let mut signatures = Vec::with_capacity(capacity);
    let mut public_keys = Vec::with_capacity(capacity);

    for transaction in transactions {
        let transaction_without_authorizations = Transaction {
            authorizations: vec![],
            ..transaction.clone()
        };
        let message = hash(&transaction_without_authorizations);
        for authorization in &transaction.authorizations {
            messages.push(message);
            signatures.push(authorization.signature);
            public_keys.push(authorization.public_key);
        }
    }
    let messages: Vec<&[u8]> = messages.iter().map(|message| message.as_slice()).collect();

    ed25519_dalek::verify_batch(
        messages.as_slice(),
        signatures.as_slice(),
        public_keys.as_slice(),
    )?;
    Ok(())
}
