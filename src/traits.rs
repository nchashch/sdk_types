use std::collections::HashMap;

pub trait UtxoMap<P, O> {
    fn get_utxo(&self, outpoint: &P) -> Option<O>;
    fn get_utxos(&self, outpoints: &[P]) -> Option<Vec<O>> {
        outpoints
            .iter()
            .map(|outpoint| self.get_utxo(outpoint))
            .collect()
    }
    fn is_spent(&self, outpoint: &P) -> bool {
        self.get_utxo(outpoint).is_none()
    }
    fn any_spent(&self, outpoints: &[P]) -> bool {
        outpoints.iter().any(|outpoint| self.is_spent(outpoint))
    }
}

impl<P: std::cmp::Eq + std::hash::Hash + Clone, O: Clone> UtxoMap<P, O> for HashMap<P, O> {
    fn get_utxo(&self, outpoint: &P) -> Option<O> {
        self.get(outpoint).cloned()
    }
}
