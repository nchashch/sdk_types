use std::collections::HashMap;


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
