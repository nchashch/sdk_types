use crate::types::*;
use serde::Serialize;
use std::collections::HashSet;

// Returns the fee paid by transaction if it is valid.
pub fn validate_transaction<C: GetValue>(
    spent_utxos: &[Output<C>],
    transaction: &Transaction<C>,
) -> Result<u64, Error> {
    // Accounting
    let (value_in, value_out) = {
        let value_in: u64 = spent_utxos.iter().map(|i| i.get_value()).sum();
        let value_out: u64 = transaction.outputs.iter().map(|o| o.get_value()).sum();
        (value_in, value_out)
    };
    if value_in < value_out {
        return Err(Error::ValueInLessThanValueOut {
            value_in,
            value_out,
        });
    }
    Ok(value_in - value_out)
}

/// Returns total fee collected by body if it is valid.
///
/// NOTE: It does not verify authorizations! It only checks if authorization
/// address matches the spent utxo address.
pub fn validate_body<A: GetAddress, C: GetValue + Clone + Serialize>(
    spent_utxos: &[Output<C>],
    body: &Body<A, C>,
) -> Result<u64, Error> {
    let mut fees: u64 = 0;

    // Authorization public key matches spent utxo address
    for (spent_utxo, authorization) in spent_utxos.iter().zip(body.authorizations.iter()) {
        let authorization_address = authorization.get_address();
        let utxo_address = spent_utxo.get_address();
        if authorization_address != utxo_address {
            return Err(Error::AddressesDontMatch {
                authorization_address,
                utxo_address,
            });
        }
    }

    // No UTXO is double spent within the same body.
    let mut seen_inputs: HashSet<OutPoint> =
        HashSet::with_capacity(body.transactions.iter().map(|t| t.inputs.len()).sum());
    for input in body
        .transactions
        .iter()
        .flat_map(|transaction| transaction.inputs.iter())
    {
        if seen_inputs.contains(input) {
            return Err(Error::DoubleSpent { input: *input });
        }
        seen_inputs.insert(*input);
    }
    {
        let mut index = 0;
        for transaction in &body.transactions {
            let spent_utxos = &spent_utxos[index..transaction.inputs.len()];
            index += transaction.inputs.len();
            fees += validate_transaction(spent_utxos, transaction)?;
        }
    }
    let coinbase_value = body.get_coinbase_value();
    if coinbase_value > fees {
        return Err(Error::CoinbaseValueGreaterThanFees {
            coinbase_value,
            fees,
        });
    }
    Ok(fees)
}

pub trait State<C> {
    type Error;
    fn validate_transaction(&self, transaction: &Transaction<C>) -> Result<(), Self::Error>;
    fn validate_body<A>(&self, body: &Body<A, C>) -> Result<(), Self::Error>;
    fn connect_body<A>(&mut self, body: &Body<A, C>) -> Result<(), Self::Error>;
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("outpoint {input} is double spent")]
    DoubleSpent { input: OutPoint },
    #[error("coinbase value > fees value: {coinbase_value} > {fees}")]
    CoinbaseValueGreaterThanFees { coinbase_value: u64, fees: u64 },
    #[error("authorization address does not match spent utxo address: {authorization_address} != {utxo_address}")]
    AddressesDontMatch {
        authorization_address: Address,
        utxo_address: Address,
    },
    #[error("transaction value in < value out: {value_in} < {value_out}")]
    ValueInLessThanValueOut { value_in: u64, value_out: u64 },
}
