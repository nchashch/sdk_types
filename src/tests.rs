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
    use std::collections::HashMap;

    #[test]
    fn test() {
        let mut blockchain = StateMachine::default();
        let mut csprng = rand::thread_rng();
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let address: Address = keypair.public.into();
        let deposit_outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_slice(&[0; 32]).unwrap(),
            vout: 2,
        };
        let deposits = {
            let deposit_output = Output::Regular {
                address,
                value: 100,
            };
            HashMap::from([(deposit_outpoint, deposit_output)])
        };
        blockchain.add_deposits(deposits);
        dbg!(&blockchain.outputs);

        let output = Output::Regular { address, value: 1 };
        let change = Output::Regular { address, value: 98 };
        let transaction = Transaction::new(
            vec![OutPoint::Deposit(deposit_outpoint)],
            vec![output, change],
        );
        let authorization = Authorization::new(&keypair, &transaction);
        let transaction = Transaction {
            authorizations: vec![authorization],
            ..transaction
        };
        let coinbase = Output::Regular {
            address,
            value: blockchain.get_fee(&transaction),
        };
        dbg!(&transaction);
        blockchain.validate_transaction(&transaction).unwrap();
        let body = Body::new(vec![transaction], vec![coinbase]);
        let header = Header::new(&Hash::default().into(), &body);

        dbg!(&blockchain.unspent_outpoints);
        blockchain.connect_block(&header, &body);
        dbg!(&blockchain.outputs);
        dbg!(&blockchain.unspent_outpoints);
    }

    #[quickcheck]
    fn test_quick(s: String) -> bool {
        let reversed: String = s.chars().rev().collect();
        let round_trip: String = reversed.chars().rev().collect();
        round_trip == s
    }
}
