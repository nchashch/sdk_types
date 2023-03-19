use crate::types::*;
use serde::Serialize;
use std::collections::HashSet;

pub trait CustomValidator<C> {
    fn custom_validate_transaction(
        &self,
        spent_utxos: &[Output<C>],
        transaction: &Transaction<C>,
    ) -> Result<(), String>;
}

// Returns the fee paid by transaction if it is valid.
pub fn regular_validate_transaction<C: GetValue>(
    spent_utxos: &[Output<C>],
    transaction: &Transaction<C>,
) -> Result<u64, String> {
    // Authorization public key matches spent utxo address
    for (spent_utxo, authorization) in spent_utxos.iter().zip(transaction.authorizations.iter()) {
        if Address::from(authorization.public_key) != spent_utxo.get_address() {
            return Err("authorization address does not match spent utxo address".into());
        }
    }

    // No double spends within transaction
    let mut seen_inputs: HashSet<OutPoint> = HashSet::with_capacity(transaction.inputs.len());
    for input in &transaction.inputs {
        if seen_inputs.contains(input) {
            return Err("utxo is double spent in transaction".into());
        }
        seen_inputs.insert(*input);
    }

    // Accounting
    let (value_in, value_out) = {
        let value_in: u64 = spent_utxos.iter().map(|i| i.get_value()).sum();
        let value_out: u64 = transaction.outputs.iter().map(|o| o.get_value()).sum();
        (value_in, value_out)
    };
    if value_in < value_out {
        return Err("value in < value out".into());
    }
    Ok(value_in - value_out)
}

pub trait Validator<C: GetValue + Clone + Serialize>: CustomValidator<C> {
    fn validate_transaction(
        &self,
        spent_utxos: &[Output<C>],
        transaction: &Transaction<C>,
    ) -> Result<u64, String> {
        self.custom_validate_transaction(spent_utxos, transaction)?;
        regular_validate_transaction(spent_utxos, transaction)
    }
    // Returns total fee collected by body if it is valid.
    fn validate_body(&self, spent_utxos: &[Vec<Output<C>>], body: &Body<C>) -> Result<u64, String> {
        let mut fees: u64 = 0;
        for (transaction, spent_utxos) in body.transactions.iter().zip(spent_utxos.iter()) {
            fees += self.validate_transaction(spent_utxos, transaction)?;
        }
        if body.get_coinbase_value() > fees {
            return Err("coinbase value > fees".into());
        }
        Ok(fees)
    }
}

pub fn verify_signatures<C: Clone + Serialize>(
    transactions: &[Transaction<C>],
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
