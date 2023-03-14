use crate::types::*;
use std::collections::{HashMap, HashSet};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct StateMachine {
    block_order: Vec<BlockHash>,
    headers: HashMap<BlockHash, Header>,
    bodies: HashMap<BlockHash, Body>,
    transactions: HashMap<Txid, Transaction>,

    pub outputs: HashMap<OutPoint, Output>,
    pub deposit_outputs: HashMap<OutPoint, DepositOutput>,
    pub withdrawal_outputs: HashMap<OutPoint, WithdrawalOutput>,
    pub unspent_outpoints: HashSet<OutPoint>,
}

impl StateMachine {
    pub fn new() -> Self {
        StateMachine {
            block_order: vec![],
            headers: HashMap::new(),
            bodies: HashMap::new(),
            transactions: HashMap::new(),
            outputs: HashMap::new(),
            deposit_outputs: HashMap::new(),
            withdrawal_outputs: HashMap::new(),
            unspent_outpoints: HashSet::new(),
        }
    }

    fn is_spent(&self, outpoint: &OutPoint) -> bool {
        !self.unspent_outpoints.contains(outpoint)
    }

    pub fn add_deposits(&mut self, deposit_outputs: HashMap<bitcoin::OutPoint, DepositOutput>) {
        let deposit_outputs: HashMap<OutPoint, DepositOutput> = deposit_outputs
            .into_iter()
            .map(|(outpoint, output)| (OutPoint::Deposit(outpoint), output))
            .collect();
        self.unspent_outpoints
            .extend(deposit_outputs.keys().cloned());
        self.deposit_outputs.extend(deposit_outputs);
    }

    pub fn validate_transaction(&self, transaction: &Transaction) -> Result<(), String> {
        let (inputs, deposit_inputs, withdrawal_inputs) = self.get_inputs(transaction);
        if Output::validate(
            &inputs,
            &deposit_inputs,
            &withdrawal_inputs,
            &transaction.outputs,
            &transaction.withdrawal_outputs,
        ) {
            return Err("value out > value in".into());
        }
        let txid_without_signatures = transaction.without_signatures().txid();
        for (outpoint, signature) in transaction.inputs.iter().zip(transaction.signatures.iter()) {
            if self.is_spent(&outpoint) {
                return Err("output spent".into());
            }
            if !signature.is_valid(txid_without_signatures) {
                return Err("wrong signature".into());
            }
            if let Some(spent_output) = self.outputs.get(&outpoint) {
                if spent_output.get_address() != signature.get_address() {
                    return Err("addresses don't match".into());
                }
            } else if let Some(spent_output) = self.withdrawal_outputs.get(&outpoint) {
                if spent_output.side_address != signature.get_address() {
                    return Err("addresses don't match".into());
                }
            } else if let Some(spent_output) = self.deposit_outputs.get(&outpoint) {
                if spent_output.address != signature.get_address() {
                    return Err("addresses don't match".into());
                }
            } else {
                return Err("output doesn't exist".into());
            }
        }
        Ok(())
    }

    pub fn validate_block(&self, header: &Header, body: &Body) -> bool {
        let best_block = self
            .get_best_block_hash()
            .unwrap_or_else(|| Hash::default().into());
        if header.prev_block_hash != best_block {
            return false;
        }
        if header.merkle_root != body.compute_merkle_root() {
            return false;
        }
        for tx in &body.transactions {
            if self.validate_transaction(tx).is_err() {
                return false;
            }
        }
        true
    }

    pub fn connect_block(&mut self, header: &Header, body: &Body) {
        for tx in &body.transactions {
            let txid = tx.txid();
            self.transactions.insert(txid, tx.clone());
            for outpoint in &tx.inputs {
                self.unspent_outpoints.remove(outpoint);
            }
            for (vout, output) in tx.outputs.iter().enumerate() {
                let vout = vout as u32;
                let outpoint = OutPoint::Regular { txid, vout };
                self.outputs.insert(outpoint, output.clone());
                self.unspent_outpoints.insert(outpoint);
            }
            for (vout, output) in tx.withdrawal_outputs.iter().enumerate() {
                let vout = vout as u32;
                let outpoint = OutPoint::Withdrawal { txid, vout };
                self.withdrawal_outputs.insert(outpoint, output.clone());
                self.unspent_outpoints.insert(outpoint);
            }
            let block_hash = header.hash();
            self.headers.insert(block_hash, header.clone());
            self.bodies.insert(block_hash, body.clone());
            self.block_order.push(block_hash);
        }
    }

    pub fn disconnect_block(&mut self, header: &Header, body: &Body) {
        for tx in &body.transactions {
            let txid = tx.txid();
            for outpoint in &tx.inputs {
                self.unspent_outpoints.insert(*outpoint);
            }
            for vout in 0..tx.outputs.len() {
                let vout = vout as u32;
                let outpoint = OutPoint::Regular { txid, vout };
                self.outputs.remove(&outpoint);
                self.unspent_outpoints.remove(&outpoint);
            }
            for vout in 0..tx.withdrawal_outputs.len() {
                let vout = vout as u32;
                let outpoint = OutPoint::Withdrawal { txid, vout };
                self.withdrawal_outputs.remove(&outpoint);
                self.unspent_outpoints.remove(&outpoint);
            }
            self.transactions.remove(&txid);
        }
        let block_hash = header.hash();
        self.bodies.remove(&block_hash);
        self.headers.remove(&block_hash);
        self.block_order.pop();
    }

    fn get_best_block_hash(&self) -> Option<BlockHash> {
        self.block_order.last().copied()
    }

    pub fn get_fee(&self, transaction: &Transaction) -> u64 {
        let (inputs, deposit_inputs, withdrawal_inputs) = self.get_inputs(transaction);
        Output::get_fee(
            &inputs,
            &deposit_inputs,
            &withdrawal_inputs,
            &transaction.outputs,
            &transaction.withdrawal_outputs,
        )
    }

    pub fn get_addresses(&self, transaction: &Transaction) -> Vec<Address> {
        transaction
            .inputs
            .iter()
            .map(|outpoint| match outpoint {
                regular @ OutPoint::Regular { .. } => self.outputs[regular].address,
                coinbase @ OutPoint::Coinbase { .. } => self.outputs[coinbase].address,
                deposit @ OutPoint::Deposit { .. } => self.deposit_outputs[deposit].address,
                withdrawal @ OutPoint::Withdrawal { .. } => {
                    self.withdrawal_outputs[withdrawal].side_address
                }
            })
            .collect()
    }

    fn get_inputs(
        &self,
        transaction: &Transaction,
    ) -> (Vec<Output>, Vec<DepositOutput>, Vec<WithdrawalOutput>) {
        let inputs: Vec<Output> = transaction
            .inputs
            .iter()
            .filter(|outpoint| self.outputs.contains_key(outpoint))
            .map(|outpoint| self.outputs[outpoint].clone())
            .collect();
        let deposit_inputs: Vec<DepositOutput> = transaction
            .inputs
            .iter()
            .filter(|outpoint| self.deposit_outputs.contains_key(outpoint))
            .map(|outpoint| self.deposit_outputs[outpoint].clone())
            .collect();
        let withdrawal_inputs: Vec<WithdrawalOutput> = transaction
            .inputs
            .iter()
            .filter(|outpoint| self.withdrawal_outputs.contains_key(outpoint))
            .map(|outpoint| self.withdrawal_outputs[outpoint].clone())
            .collect();
        (inputs, deposit_inputs, withdrawal_inputs)
    }
}
