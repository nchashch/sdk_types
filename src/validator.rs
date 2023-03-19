use crate::traits::*;
use crate::types::*;
use ed25519_dalek::Verifier;
use serde::Serialize;

pub trait CustomValidator<C> {
    fn custom_validate_transaction(
        &self,
        spent_utxos: &[Output<C>],
        transaction: &Transaction<C>,
    ) -> Result<(), String>;
}

pub trait RegularValidator<C: GetValue> {
    // Returns the fee paid by transaction if it is valid.
    fn regular_validate_transaction(
        &self,
        spent_utxos: &[Output<C>],
        transaction: &Transaction<C>,
    ) -> Result<u64, String> {
        // Authorization public key matches spent utxo address
        for (spent_utxo, authorization) in spent_utxos.iter().zip(transaction.authorizations.iter())
        {
            if Address::from(authorization.public_key) != spent_utxo.get_address() {
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
}

pub trait Validator<C: GetValue + Clone + Serialize>:
    RegularValidator<C> + CustomValidator<C>
{
    fn validate_transaction(
        &self,
        spent_utxos: &[Output<C>],
        transaction: &Transaction<C>,
    ) -> Result<u64, String> {
        self.custom_validate_transaction(spent_utxos, transaction)?;
        self.regular_validate_transaction(spent_utxos, transaction)
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

pub struct AuthorizationValidator;

impl AuthorizationValidator {
    pub fn verify_signatures<C: Clone + Serialize>(
        &self,
        transactions: &[Transaction<C>],
    ) -> Result<(), ed25519_dalek::SignatureError> {
        for transaction in transactions {
            let transaction = Transaction {
                authorizations: vec![],
                ..transaction.clone()
            };
            let transaction_hash_without_authorizations = hash(&transaction);
            for authorization in &transaction.authorizations {
                authorization.public_key.verify(
                    &transaction_hash_without_authorizations,
                    &authorization.signature,
                )?;
            }
        }
        Ok(())
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
