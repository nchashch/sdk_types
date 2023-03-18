use crate::traits::*;
use crate::types::*;
use serde::{Deserialize, Serialize};

pub trait CustomValidator<R> {
    fn validate(transaction: &Transaction<R>, spent_utxos: &[Output<R>]) -> Result<(), String>;
}

impl<
        V: UtxoMap<OutPoint, Output<R>>,
        R: Clone + CustomValidator<R> + GetValue + Serialize + for<'de> Deserialize<'de>,
    > Validator<R> for V
{
    fn validate_transaction(&self, transaction: &Transaction<R>) -> Result<(), String> {
        let mut spent_utxos = vec![];
        for utxo in self.get_utxos(&transaction.inputs) {
            match utxo {
                Some(utxo) => spent_utxos.push(utxo),
                None => return Err("utxo is double spent".into()),
            };
        }

        // Authorization
        {
            let txid_without_authorizations = transaction.without_authorizations().txid();
            for (spent_utxo, authorization) in
                spent_utxos.iter().zip(transaction.authorizations.iter())
            {
                if authorization.get_address() != spent_utxo.get_address() {
                    return Err("authorization address does not match spent utxo address".into());
                }
                if !authorization.is_valid(&txid_without_authorizations) {
                    return Err("invalid authorization".into());
                }
            }
        }

        // Accounting
        {
            let (value_in, value_out) = {
                let value_in: u64 = spent_utxos.iter().map(|i| i.get_value()).sum();
                let value_out: u64 = transaction.outputs.iter().map(|o| o.get_value()).sum();
                (value_in, value_out)
            };
            if value_in < value_out {
                return Err("value in < value out".into());
            }
        }
        R::validate(transaction, &spent_utxos)?;
        Ok(())
    }
}

pub trait Validator<
    R: Clone + CustomValidator<R> + GetValue + Serialize + for<'de> Deserialize<'de>,
>
{
    fn validate_transaction(&self, transaction: &Transaction<R>) -> Result<(), String>;
}
