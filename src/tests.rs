#[cfg(test)]
use fake::{Dummy, Fake, Faker};
#[cfg(test)]
use quickcheck_macros::quickcheck;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use bitcoin::hashes::Hash as _;
    use ed25519_dalek::Keypair;
    use rand::{CryptoRng, Rng, RngCore};
    use std::collections::{HashMap, HashSet};

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
    ) -> (Transaction<Custom>, HashSet<OutPoint>) {
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
        let transaction = Transaction::new(inputs.clone(), outputs);
        let txid_without_authorizations = transaction.without_authorizations().txid();
        let authorizations = addresses
            .iter()
            .map(|address| Authorization::new(&keypairs[&address], &txid_without_authorizations))
            .collect();
        (
            Transaction {
                authorizations,
                ..transaction
            },
            inputs.into_iter().collect(),
        )
    }

    fn random_body(
        transactions: Vec<Transaction<Custom>>,
        num_coinbase_outputs: usize,
        outputs: &HashMap<OutPoint, Output<Custom>>,
        keypairs: &HashMap<Address, Keypair>,
    ) -> Body<Custom> {
        let addresses: Vec<Address> = keypairs.keys().copied().collect();
        let fee: u64 = transactions
            .iter()
            .map(|tx| tx.get_fee(outputs).unwrap())
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

    impl Transaction<Custom> {
        fn foo() {}
    }

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
        body.validate(&utxo_map);
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
}
