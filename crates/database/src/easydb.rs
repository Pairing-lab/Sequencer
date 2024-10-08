use revm_primitives::{hash_map::Entry, Account, AccountInfo, Address, Bytecode, HashMap, Log, B256, KECCAK_EMPTY,
    U256,};
use revm::Database;
use core::convert::Infallible;


#[derive(Debug, Default, Clone)]
pub struct EasyDB(pub Bytecode, B256);

impl EasyDB {
    pub fn new_bytecode(bytecode: Bytecode) -> Self {
        let hash = bytecode.hash_slow();
        Self(bytecode, hash)
    }
}

impl Database for EasyDB {
    type Error = Infallible;
    /// Get basic account information.
    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        if address == Address::ZERO {
            return Ok(Some(AccountInfo {
                nonce: 1,
                balance: U256::from(10000000),
                code: Some(self.0.clone()),
                code_hash: self.1,
            }));
        }
        if address == Address::with_last_byte(1) {
            return Ok(Some(AccountInfo {
                nonce: 0,
                balance: U256::from(10000000),
                code: None,
                code_hash: KECCAK_EMPTY,
            }));
        }
        Ok(None)
    }
    /// Get account code by its hash
    fn code_by_hash(&mut self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        Ok(Bytecode::default())
    }
    /// Get storage value of address at index.
    fn storage(&mut self, _address: Address, _index: U256) -> Result<U256, Self::Error> {
        Ok(U256::default())
    }
    // History related
    fn block_hash(&mut self, _number: u64) -> Result<B256, Self::Error> {
        Ok(B256::default())
    }
}
