use crate::types::*;
use std::collections::{HashMap, HashSet};

#[derive(Default, Debug, serde::Serialize, serde::Deserialize)]
pub struct StateMachine {
    block_order: Vec<BlockHash>,
    headers: HashMap<BlockHash, Header>,
    pub outputs: HashMap<OutPoint, Output>,
    pub unspent_outpoints: HashSet<OutPoint>,
}

impl StateMachine {
    fn is_spent(&self, outpoint: &OutPoint) -> bool {
        !self.unspent_outpoints.contains(outpoint)
    }

    pub fn get_unspent_withdrawals(&self) -> HashMap<OutPoint, sdk::WithdrawalOutput> {
        let mut withdrawals = HashMap::new();
        for outpoint in &self.unspent_outpoints {
            let output = self.outputs[outpoint].clone();
            let withdrawal = match output {
                Output::Withdrawal {
                    main_address,
                    main_fee,
                    value,
                    ..
                } => sdk::WithdrawalOutput {
                    address: main_address,
                    fee: main_fee,
                    value,
                },
                _ => continue,
            };
            withdrawals.insert(*outpoint, withdrawal);
        }
        withdrawals
    }

    pub fn connect_main_block(
        &mut self,
        deposit_outputs: HashMap<OutPoint, Output>,
        locked_withdrawal_outpoints: &[OutPoint],
        unlocked_withdrawal_outputs: HashMap<OutPoint, Output>,
    ) {
        self.unspent_outpoints.extend(deposit_outputs.keys());
        self.outputs.extend(deposit_outputs);
        for outpoint in locked_withdrawal_outpoints {
            self.unspent_outpoints.remove(outpoint);
        }
        self.unspent_outpoints
            .extend(unlocked_withdrawal_outputs.keys());
        self.outputs.extend(unlocked_withdrawal_outputs);
    }

    pub fn disconnect_main_block(
        &mut self,
        deposit_outpoints: &[OutPoint],
        locked_withdrawal_outputs: HashMap<OutPoint, Output>,
        unlocked_withdrawal_outpoints: &[OutPoint],
    ) {
        for outpoint in deposit_outpoints {
            self.unspent_outpoints.remove(outpoint);
            self.outputs.remove(outpoint);
        }
        self.unspent_outpoints
            .extend(locked_withdrawal_outputs.keys());
        for outpoint in unlocked_withdrawal_outpoints {
            self.unspent_outpoints.remove(outpoint);
        }
        self.outputs.extend(locked_withdrawal_outputs);
    }

    pub fn validate_transaction(&self, transaction: &Transaction) -> Result<(), String> {
        let (value_in, value_out) = {
            let inputs = self.get_inputs(transaction);
            let value_in: u64 = inputs.iter().map(|i| i.get_value()).sum();
            let value_out: u64 = transaction.outputs.iter().map(|o| o.get_value()).sum();
            (value_in, value_out)
        };
        if value_in < value_out {
            return Err("value in < value out".into());
        }
        let txid_without_authorizations = transaction.without_authorizations().txid();
        if transaction.inputs.len() != transaction.authorizations.len() {
            return Err("not enough authorizations".into());
        }
        for (outpoint, authorization) in transaction
            .inputs
            .iter()
            .zip(transaction.authorizations.iter())
        {
            if self.is_spent(outpoint) {
                return Err("output spent".into());
            }
            if !authorization.is_valid(txid_without_authorizations) {
                return Err("invalid authorization".into());
            }
            if let Some(spent_output) = self.outputs.get(outpoint) {
                if spent_output.get_address() != authorization.get_address() {
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
        if header.prev_side_block_hash != best_block {
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
        let fees: u64 = body.transactions.iter().map(|tx| self.get_fee(tx)).sum();
        let coinbase_value: u64 = body.coinbase.iter().map(|output| output.get_value()).sum();
        if coinbase_value > fees {
            return false;
        }
        true
    }

    pub fn connect_block(&mut self, header: &Header, body: &Body) {
        let block_hash = header.hash();
        for (vout, output) in body.coinbase.iter().enumerate() {
            let vout = vout as u32;
            let outpoint = OutPoint::Coinbase { block_hash, vout };
            self.outputs.insert(outpoint, output.clone());
            self.unspent_outpoints.insert(outpoint);
        }
        for tx in &body.transactions {
            let txid = tx.txid();
            for outpoint in &tx.inputs {
                self.unspent_outpoints.remove(outpoint);
            }
            for (vout, output) in tx.outputs.iter().enumerate() {
                let vout = vout as u32;
                let outpoint = OutPoint::Regular { txid, vout };
                self.outputs.insert(outpoint, output.clone());
                self.unspent_outpoints.insert(outpoint);
            }
            let block_hash = header.hash();
            self.headers.insert(block_hash, header.clone());
            self.block_order.push(block_hash);
        }
    }

    pub fn disconnect_block(&mut self, header: &Header, body: &Body) {
        let block_hash = header.hash();
        for vout in 0..body.coinbase.len() {
            let vout = vout as u32;
            let outpoint = OutPoint::Coinbase { block_hash, vout };
            self.outputs.remove(&outpoint);
            self.unspent_outpoints.remove(&outpoint);
        }
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
        }
        let block_hash = header.hash();
        self.headers.remove(&block_hash);
        self.block_order.pop();
    }

    fn get_best_block_hash(&self) -> Option<BlockHash> {
        self.block_order.last().copied()
    }

    pub fn get_addresses(&self, transaction: &Transaction) -> Vec<Address> {
        transaction
            .inputs
            .iter()
            .map(|outpoint| self.outputs[outpoint].get_address())
            .collect()
    }

    pub fn get_inputs(&self, transaction: &Transaction) -> Vec<Output> {
        transaction
            .inputs
            .iter()
            .map(|outpoint| self.outputs[outpoint].clone())
            .collect()
    }

    pub fn get_fee(&self, transaction: &Transaction) -> u64 {
        let inputs = self.get_inputs(transaction);
        let value_in: u64 = inputs.iter().map(|i| i.get_value()).sum();
        let value_out: u64 = transaction.outputs.iter().map(|o| o.get_value()).sum();
        value_in - value_out
    }
}
