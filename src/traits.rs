use std::collections::{HashMap, HashSet};

pub trait UtxoSet<P> {
    fn is_spent(&self, outpoint: &P) -> bool;
}

pub trait OutputStore<P, O> {
    fn get_output(&self, outpoint: &P) -> Option<&O>;
}

impl<P: std::cmp::Eq + std::hash::Hash + Clone> UtxoSet<P> for HashSet<P> {
    fn is_spent(&self, outpoint: &P) -> bool {
        self.contains(outpoint)
    }
}

impl<'a, P: std::cmp::Eq + std::hash::Hash + Clone + 'a, O: 'a> OutputStore<P, O>
    for HashMap<P, O>
{
    fn get_output(&self, outpoint: &P) -> Option<&O> {
        self.get(outpoint)
    }
}
