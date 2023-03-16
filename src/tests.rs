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
    ) -> HashMap<OutPoint, Output> {
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

    fn random_outputs(num_outputs: usize, value_in: u64, addresses: &[Address]) -> Vec<Output> {
        let value = value_in / (num_outputs as u64);
        (0..num_outputs)
            .map(|_| {
                let index: usize = (0..addresses.len()).fake();
                let address = addresses[index];
                Output::Regular { value, address }
            })
            .collect()
    }

    fn random_transaction(
        num_inputs: usize,
        num_outputs: usize,
        unspent_outpoints: &HashSet<OutPoint>,
        state_machine: &StateMachine,
        keypairs: &HashMap<Address, Keypair>,
    ) -> (Transaction, HashSet<OutPoint>) {
        let addresses: Vec<Address> = keypairs.keys().copied().collect();
        let (inputs, addresses) = {
            let outpoints: Vec<OutPoint> =
                state_machine.unspent_outpoints.iter().copied().collect();
            let inputs: Vec<OutPoint> = (0..num_inputs)
                .map(|_| {
                    let index: usize = (0..outpoints.len()).fake();
                    outpoints[index]
                })
                .collect();
            let addresses: Vec<Address> = inputs
                .iter()
                .map(|outpoint| state_machine.outputs[outpoint].get_address())
                .collect();
            (inputs, addresses)
        };
        let value_in: u64 = inputs
            .iter()
            .map(|outpoint| state_machine.outputs[outpoint].get_value())
            .sum();
        let outputs = random_outputs(num_outputs, value_in, &addresses);
        let transaction = Transaction::new(inputs.clone(), outputs);
        let authorizations = addresses
            .iter()
            .map(|address| Authorization::new(&keypairs[&address], &transaction))
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
        transactions: Vec<Transaction>,
        num_coinbase_outputs: usize,
        state_machine: &StateMachine,
        keypairs: &HashMap<Address, Keypair>,
    ) -> Body {
        let addresses: Vec<Address> = keypairs.keys().copied().collect();
        let fee: u64 = transactions
            .iter()
            .map(|tx| state_machine.get_fee(tx))
            .sum();
        let coinbase = random_outputs(num_coinbase_outputs, fee, &addresses);
        Body::new(transactions, coinbase)
    }

    #[test]
    fn test() {
        let keypairs = random_keypairs(10);
        let addresses: Vec<Address> = keypairs.keys().copied().collect();
        let deposit_outputs = random_deposits(15, &addresses);
        let mut state_machine = StateMachine::default();
        state_machine.connect_main_block(deposit_outputs.clone(), &[], HashMap::new());
        let mut unspent_outpoints = state_machine.unspent_outpoints.clone();
        let transactions = (0..10)
            .map(|_| {
                let (transaction, spent_outpoints) =
                    random_transaction(1, 1, &unspent_outpoints, &state_machine, &keypairs);
                unspent_outpoints = unspent_outpoints
                    .difference(&spent_outpoints)
                    .copied()
                    .collect();
                transaction
            })
            .collect();

        let body = random_body(transactions, 1, &state_machine, &keypairs);
        state_machine
            .validate_transaction(&body.transactions[0])
            .unwrap();
        let header = Header::new(
            [0; 32].into(),
            bitcoin::BlockHash::from_inner([0; 32]),
            &body,
        );
        state_machine.connect_block(&header, &body);
    }

    #[quickcheck]
    fn test_quick(s: String) -> bool {
        let reversed: String = s.chars().rev().collect();
        let round_trip: String = reversed.chars().rev().collect();
        round_trip == s
    }
}
