use crate::types::*;
use serde::Serialize;
use std::collections::HashSet;

pub trait CustomValidator<A, C> {
    fn custom_validate_transaction(
        &self,
        spent_utxos: &[Output<C>],
        transaction: &Transaction<A, C>,
    ) -> Result<(), String>;
}

// Returns the fee paid by transaction if it is valid.
pub fn regular_validate_transaction<A: GetAddress, C: GetValue>(
    spent_utxos: &[Output<C>],
    transaction: &Transaction<A, C>,
) -> Result<u64, String> {
    // Authorization public key matches spent utxo address
    for (spent_utxo, authorization) in spent_utxos.iter().zip(transaction.authorizations.iter()) {
        if authorization.get_address() != spent_utxo.get_address() {
            return Err("authorization address does not match spent utxo address".into());
        }
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

pub trait Validator<A: GetAddress + Serialize, C: GetValue + Clone + Serialize>:
    CustomValidator<A, C>
{
    fn validate_transaction(
        &self,
        spent_utxos: &[Output<C>],
        transaction: &Transaction<A, C>,
    ) -> Result<u64, String> {
        self.custom_validate_transaction(spent_utxos, transaction)?;
        regular_validate_transaction(spent_utxos, transaction)
    }
    // Returns total fee collected by body if it is valid.
    fn validate_body(
        &self,
        spent_utxos: &[Vec<Output<C>>],
        body: &Body<A, C>,
    ) -> Result<u64, String> {
        let mut fees: u64 = 0;

        // No UTXO is double spent within the same body.
        let mut seen_inputs: HashSet<OutPoint> = body
            .transactions
            .iter()
            .flat_map(|transaction| transaction.inputs.iter().copied())
            .collect();
        for input in body
            .transactions
            .iter()
            .flat_map(|transaction| transaction.inputs.iter())
        {
            if seen_inputs.contains(input) {
                return Err("utxo is double spent in transaction".into());
            }
            seen_inputs.insert(*input);
        }

        for (transaction, spent_utxos) in body.transactions.iter().zip(spent_utxos.iter()) {
            fees += self.validate_transaction(spent_utxos, transaction)?;
        }
        if body.get_coinbase_value() > fees {
            return Err("coinbase value > fees".into());
        }
        Ok(fees)
    }
}
