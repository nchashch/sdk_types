#[cfg(test)]
use fake::{Dummy, Fake, Faker};
#[cfg(test)]
use quickcheck_macros::quickcheck;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dalek_authorization::*;
    use crate::*;
    use bitcoin::hashes::Hash as _;
    use ed25519_dalek::{Keypair, Signer};
    use rand::{CryptoRng, Rng, RngCore};
    use std::collections::{HashMap, HashSet};

    type CTransaction = Transaction<Authorization, Custom>;
    type CBody = Body<Authorization, Custom>;

    fn random_keypairs(num_keys: usize) -> HashMap<Address, Keypair> {
        let mut csprng = rand::thread_rng();
        let mut keypairs = HashMap::new();
        for _ in 0..num_keys {
            let keypair: Keypair = Keypair::generate(&mut csprng);
            let address: Address = keypair.public.into();
            keypairs.insert(address, keypair);
        }
        keypairs
    }

    fn random_deposits(
        num_deposits: usize,
        addresses: &[Address],
    ) -> HashMap<OutPoint, Output<Custom>> {
        const MAX_MONEY: u64 = 21_000_000_00_000_000;
        (0..num_deposits)
            .map(|_| {
                let outpoint = {
                    let txid: [u8; 32] = Faker.fake();
                    let txid = bitcoin::Txid::from_inner(txid);
                    let vout: u32 = (0..100).fake();
                    OutPoint::Deposit(bitcoin::OutPoint { txid, vout })
                };
                let output = {
                    let value = (0..MAX_MONEY).fake();
                    let index: usize = (0..addresses.len()).fake();
                    let address = addresses[index];
                    Output::Regular { address, value }
                };
                (outpoint, output)
            })
            .collect()
    }

    fn random_outputs(
        num_outputs: usize,
        value_in: u64,
        addresses: &[Address],
    ) -> Vec<Output<Custom>> {
        let value = value_in / (num_outputs as u64);
        (0..num_outputs)
            .map(|_| {
                let index: usize = (0..addresses.len()).fake();
                let address = addresses[index];
                Output::Regular { address, value }
            })
            .collect()
    }

    fn random_transaction(
        num_inputs: usize,
        num_outputs: usize,
        unspent_outpoints: &HashSet<OutPoint>,
        utxo_set: &HashSet<OutPoint>,
        outputs: &HashMap<OutPoint, Output<Custom>>,
        keypairs: &HashMap<Address, Keypair>,
    ) -> (CTransaction, HashSet<OutPoint>) {
        let addresses: Vec<Address> = keypairs.keys().copied().collect();
        let (inputs, addresses) = {
            let outpoints: Vec<OutPoint> = utxo_set.iter().copied().collect();
            let inputs: Vec<OutPoint> = (0..num_inputs)
                .map(|_| {
                    let index: usize = (0..outpoints.len()).fake();
                    outpoints[index]
                })
                .collect();
            let addresses: Vec<Address> = inputs
                .iter()
                .map(|outpoint| outputs[outpoint].get_address())
                .collect();
            (inputs, addresses)
        };
        let value_in: u64 = inputs
            .iter()
            .map(|outpoint| outputs[outpoint].get_value())
            .sum();
        let outputs = random_outputs(num_outputs, value_in, &addresses);
        let transaction = CTransaction {
            inputs: inputs.clone(),
            outputs,
            authorizations: vec![],
        };
        let transaction_hash_without_authorizations = hash(&transaction);
        let authorizations = addresses
            .iter()
            .map(|address| Authorization {
                signature: keypairs[address].sign(&transaction_hash_without_authorizations),
                public_key: keypairs[address].public,
            })
            .collect();
        (
            CTransaction {
                authorizations,
                ..transaction
            },
            inputs.into_iter().collect(),
        )
    }

    fn random_body(
        transactions: Vec<CTransaction>,
        num_coinbase_outputs: usize,
        outputs: &HashMap<OutPoint, Output<Custom>>,
        keypairs: &HashMap<Address, Keypair>,
    ) -> CBody {
        let addresses: Vec<Address> = keypairs.keys().copied().collect();
        let fee: u64 = transactions
            .iter()
            .map(|tx| get_fee(&outputs, &tx).unwrap())
            .sum();
        let coinbase = random_outputs(num_coinbase_outputs, fee, &addresses);
        Body::new(transactions, coinbase)
    }

    type Custom = ();
    impl GetValue for () {
        fn get_value(&self) -> u64 {
            0
        }
    }

    impl CTransaction {
        fn foo() {}
    }

    use validator::{CustomValidator, Validator};

    fn get_fee(
        utxos: &HashMap<OutPoint, Output<Custom>>,
        transaction: &CTransaction,
    ) -> Result<u64, String> {
        let mut spent_utxos = vec![];
        for utxo in utxos.get_utxos(&transaction.inputs) {
            match utxo {
                Some(utxo) => spent_utxos.push(utxo),
                None => return Err("utxo is double spent".into()),
            };
        }
        regular_validate_transaction(&spent_utxos, transaction)
    }
    impl CustomValidator<Authorization, Custom> for HashMap<OutPoint, Output<Custom>> {
        fn custom_validate_transaction(
            &self,
            spent_utxos: &[Output<Custom>],
            transactino: &CTransaction,
        ) -> Result<(), String> {
            Ok(())
        }
    }
    impl Validator<Authorization, Custom> for HashMap<OutPoint, Output<Custom>> {}

    #[test]
    fn test() {
        let keypairs = random_keypairs(10);
        let addresses: Vec<Address> = keypairs.keys().copied().collect();
        let deposit_outputs = random_deposits(5, &addresses);

        let mut utxo_map: HashMap<OutPoint, Output<Custom>> = HashMap::new();

        utxo_map.extend(deposit_outputs);
        let mut utxo_set = HashSet::new();
        utxo_set.extend(utxo_map.keys());
        let mut unspent_outpoints = utxo_set.clone();
        let transactions = (0..2)
            .map(|_| {
                let (transaction, spent_outpoints) =
                    random_transaction(1, 1, &unspent_outpoints, &utxo_set, &utxo_map, &keypairs);
                unspent_outpoints = unspent_outpoints
                    .difference(&spent_outpoints)
                    .copied()
                    .collect();
                transaction
            })
            .collect();

        let body = random_body(transactions, 1, &utxo_map, &keypairs);
        dbg!(verify_signatures(&body.transactions).unwrap());

        let body_spent_utxos: Vec<Vec<Output<Custom>>> = body
            .transactions
            .iter()
            .map(|transaction| {
                let spent_utxos: Vec<Output<Custom>> = utxo_map
                    .get_utxos(&transaction.inputs)
                    .into_iter()
                    .collect::<Option<_>>()
                    .unwrap();
                spent_utxos
            })
            .collect();

        dbg!(utxo_map.validate_body(&body_spent_utxos, &body).unwrap());
        dbg!(&utxo_map);
        {
            let inputs = body.get_inputs();
            let new_outputs = body.get_outputs();
            for input in &inputs {
                utxo_set.remove(input);
            }
            utxo_set.extend(new_outputs.keys());
            utxo_map.extend(new_outputs);
        }
        dbg!(&utxo_map);
        dbg!(body.coinbase.len());
        dbg!(body.transactions.len());
        dbg!(body.transactions);
    }

    pub trait UtxoMap<P, O> {
        fn get_utxos(&self, outpoints: &[P]) -> Vec<Option<O>>;
    }

    impl<P: std::cmp::Eq + std::hash::Hash + Clone, O: Clone> UtxoMap<P, O> for HashMap<P, O> {
        fn get_utxos(&self, outpoints: &[P]) -> Vec<Option<O>> {
            outpoints
                .iter()
                .map(|outpoint| self.get(outpoint).cloned())
                .collect()
        }
    }
}
