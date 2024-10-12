use crate::{
    Arc,
    RwLock,
    HashMap
};
#[derive(Clone, Debug)]
pub struct Transaction {
    pub hash: String,
    pub data: Vec<u8>,
}
pub struct Mempool {
    transactions: Arc<RwLock<HashMap<String, Transaction>>>,
    max_size: usize,
}
impl Mempool {
    pub fn new(max_size: usize) -> Self {
        Mempool {
            transactions: Arc::new(RwLock::new(HashMap::new())),
            max_size,
        }
    }
    pub async fn add_transaction(&self, tx: Transaction) -> Result<(), String> {
        let mut txs = self.transactions.write().await;
        if txs.len() >= self.max_size {
            return Err("Mempool is full".to_string());
        }
        txs.insert(tx.hash.clone(), tx);
        Ok(())
    }
    pub async fn get_transaction(&self, hash: &str) -> Option<Transaction> {
        let txs = self.transactions.read().await;
        txs.get(hash).cloned()
    }
    pub async fn remove_transaction(&self, hash: &str) -> Option<Transaction> {
        let mut txs = self.transactions.write().await;
        txs.remove(hash)
    }
    pub async fn get_all_transactions(&self) -> Vec<Transaction> {
        let txs = self.transactions.read().await;
        txs.values().cloned().collect()
    }
}