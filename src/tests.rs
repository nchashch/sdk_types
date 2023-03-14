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
        let mut blockchain = StateMachine::new();
        let mut csprng = rand::thread_rng();
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let address: Address = keypair.public.into();
        let deposit_outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_slice(&[0; 32]).unwrap(),
            vout: 2,
        };
        let deposits = {
            let deposit_output = DepositOutput {
                address,
                value: 100,
            };
            HashMap::from([(deposit_outpoint, deposit_output)])
        };
        blockchain.add_deposits(deposits);
        dbg!(&blockchain.outputs);

        let output = Output { address, value: 1 };
        let change = Output { address, value: 98 };
        let transaction = Transaction::new(
            vec![OutPoint::Deposit(deposit_outpoint)],
            vec![output, change],
            vec![],
        );
        let coinbase = Output {
            address,
            value: blockchain.get_fee(&transaction),
        };
        let body = Body::new(vec![transaction], vec![coinbase]);
        let header = Header::new(&Hash::default().into(), &body);
        dbg!(blockchain.validate_block(&header, &body));

        dbg!(&blockchain.unspent_outpoints);
        dbg!(blockchain.connect_block(&header, &body));
        dbg!(&blockchain.unspent_outpoints);

        dbg!(&header, &body);
    }

    #[quickcheck]
    fn test_quick(s: String) -> bool {
        let reversed: String = s.chars().rev().collect();
        let round_trip: String = reversed.chars().rev().collect();
        round_trip == s
    }
}
