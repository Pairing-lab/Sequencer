#[derive(Debug, Clone)]
pub enum EthereumRpcMethod {
    // eth namespace
    EthAccounts,
    EthBlockNumber,
    EthCall,
    EthEstimateGas,
    EthGasPrice,
    EthGetBalance,
    EthGetBlockByHash,
    EthGetBlockByNumber,
    EthGetCode,
    EthGetFilterChanges,
    EthGetFilterLogs,
    EthGetLogs,
    EthGetStorageAt,
    EthGetTransactionByHash,
    EthGetTransactionReceipt,
    EthNewBlockFilter,
    EthNewFilter,
    EthNewPendingTransactionFilter,
    EthSendRawTransaction,
    EthSendTransaction,
    EthSign,
    EthSyncing,

    // net namespace
    NetListening,
    NetPeerCount,
    NetVersion,

    // web3 namespace
    Web3ClientVersion,

    // personal namespace
    PersonalListAccounts,
    PersonalNewAccount,
    PersonalUnlockAccount,
}

impl EthereumRpcMethod {
    fn to_string(&self) -> String {
        match self {
            EthereumRpcMethod::EthAccounts => "eth_accounts".to_string(),
            EthereumRpcMethod::EthBlockNumber => "eth_blockNumber".to_string(),
            EthereumRpcMethod::EthCall => "eth_call".to_string(),
            EthereumRpcMethod::EthEstimateGas => "eth_estimateGas".to_string(),
            EthereumRpcMethod::EthGasPrice => "eth_gasPrice".to_string(),
            EthereumRpcMethod::EthGetBalance => "eth_getBalance".to_string(),
            EthereumRpcMethod::EthGetBlockByHash => "eth_getBlockByHash".to_string(),
            EthereumRpcMethod::EthGetBlockByNumber => "eth_getBlockByNumber".to_string(),
            EthereumRpcMethod::EthGetCode => "eth_getCode".to_string(),
            EthereumRpcMethod::EthGetFilterChanges => "eth_getFilterChanges".to_string(),
            EthereumRpcMethod::EthGetFilterLogs => "eth_getFilterLogs".to_string(),
            EthereumRpcMethod::EthGetLogs => "eth_getLogs".to_string(),
            EthereumRpcMethod::EthGetStorageAt => "eth_getStorageAt".to_string(),
            EthereumRpcMethod::EthGetTransactionByHash => "eth_getTransactionByHash".to_string(),
            EthereumRpcMethod::EthGetTransactionReceipt => "eth_getTransactionReceipt".to_string(),
            EthereumRpcMethod::EthNewBlockFilter => "eth_newBlockFilter".to_string(),
            EthereumRpcMethod::EthNewFilter => "eth_newFilter".to_string(),
            EthereumRpcMethod::EthNewPendingTransactionFilter => "eth_newPendingTransactionFilter".to_string(),
            EthereumRpcMethod::EthSendRawTransaction => "eth_sendRawTransaction".to_string(),
            EthereumRpcMethod::EthSendTransaction => "eth_sendTransaction".to_string(),
            EthereumRpcMethod::EthSign => "eth_sign".to_string(),
            EthereumRpcMethod::EthSyncing => "eth_syncing".to_string(),
            EthereumRpcMethod::NetListening => "net_listening".to_string(),
            EthereumRpcMethod::NetPeerCount => "net_peerCount".to_string(),
            EthereumRpcMethod::NetVersion => "net_version".to_string(),
            EthereumRpcMethod::Web3ClientVersion => "web3_clientVersion".to_string(),
            EthereumRpcMethod::PersonalListAccounts => "personal_listAccounts".to_string(),
            EthereumRpcMethod::PersonalNewAccount => "personal_newAccount".to_string(),
            EthereumRpcMethod::PersonalUnlockAccount => "personal_unlockAccount".to_string(),
        }
    }
}