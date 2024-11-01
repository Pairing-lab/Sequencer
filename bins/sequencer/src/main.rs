//! Example illustrating how to run the ETH JSON RPC API as standalone over a DB file.
//!
//! Run with
//!
//! ```not_rust
//! cargo run -p rpc-db
//! ```
//!
//! This installs an additional RPC method `myrpcExt_customMethod` that can queried via [cast](https://github.com/foundry-rs/foundry)
//!
//! ```sh
//! cast rpc myrpcExt_customMethod
//! ```
use std::sync::Arc;

use alloy_network::AnyNetwork;
use alloy_primitives::U256;
use derive_more::Deref;
use reth::api::node::BuilderProvider;
use reth_node_api::{FullNodeComponents};
use reth_primitives::BlockNumberOrTag;
use reth_provider::{CanonStateSubscriptions, ChainSpecProvider};
use reth_rpc_eth_api::{
    helpers::{EthSigner, SpawnBlocking},
    EthApiTypes,
};
use reth_rpc_eth_types::{
    EthApiBuilderCtx, EthApiError, EthStateCache, FeeHistoryCache, GasCap, GasPriceOracle,
    PendingBlock,
};
use reth_tasks::{
    pool::{BlockingTaskGuard, BlockingTaskPool},
    TaskExecutor, TaskSpawner, TokioTaskExecutor,
};
use tokio::sync::Mutex;
use reth_rpc::eth::EthTxBuilder;


// Custom rpc extension
pub mod myrpc_ext;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    
    

    Ok(())
}


#[cfg(test)]
mod tests {
    use alloy_primitives::{B256, U64};
    use jsonrpsee_types::error::INVALID_PARAMS_CODE;
    use reth_chainspec::{BaseFeeParams, ChainSpec};
    use reth_evm_ethereum::EthEvmConfig;
    use reth_network_api::noop::NoopNetwork;
    use reth_primitives::{Block, BlockBody, BlockNumberOrTag, Header, TransactionSigned};
    use reth_provider::{
        test_utils::{MockEthProvider, NoopProvider},
        BlockReader, BlockReaderIdExt, ChainSpecProvider, EvmEnvProvider, StateProviderFactory,
    };
    use reth_rpc_eth_api::EthApiServer;
    use reth_rpc_eth_types::{
        EthStateCache, FeeHistoryCache, FeeHistoryCacheConfig, GasPriceOracle,
    };
    use reth_rpc_server_types::constants::{
        DEFAULT_ETH_PROOF_WINDOW, DEFAULT_MAX_SIMULATE_BLOCKS, DEFAULT_PROOF_PERMITS,
    };
    use reth_tasks::pool::BlockingTaskPool;
    use reth_testing_utils::{generators, generators::Rng};
    use reth_transaction_pool::test_utils::{testing_pool, TestPool};
    use reth_rpc::eth::EthApi;



    fn build_test_eth_api<
        P: BlockReaderIdExt
            + BlockReader
            + ChainSpecProvider<ChainSpec = ChainSpec>
            + EvmEnvProvider
            + StateProviderFactory
            + Unpin
            + Clone
            + 'static,
    >(
        provider: P,
    ) -> EthApi<P, TestPool, NoopNetwork, EthEvmConfig> {
        let evm_config = EthEvmConfig::new(provider.chain_spec());
        let cache = EthStateCache::spawn(provider.clone(), Default::default(), evm_config.clone());
        let fee_history_cache =
            FeeHistoryCache::new(cache.clone(), FeeHistoryCacheConfig::default());

        let gas_cap = provider.chain_spec().max_gas_limit;
        EthApi::new(
            provider.clone(),
            testing_pool(),
            NoopNetwork::default(),
            cache.clone(),
            GasPriceOracle::new(provider, Default::default(), cache),
            gas_cap,
            DEFAULT_MAX_SIMULATE_BLOCKS,
            DEFAULT_ETH_PROOF_WINDOW,
            BlockingTaskPool::build().expect("failed to build tracing pool"),
            fee_history_cache,
            evm_config,
            DEFAULT_PROOF_PERMITS,
        )
    }

    // Function to prepare the EthApi with mock data
    fn prepare_eth_api(
        newest_block: u64,
        mut oldest_block: Option<B256>,
        block_count: u64,
        mock_provider: MockEthProvider,
    ) -> (EthApi<MockEthProvider, TestPool, NoopNetwork, EthEvmConfig>, Vec<u128>, Vec<f64>) {
        let mut rng = generators::rng();

        // Build mock data
        let mut gas_used_ratios = Vec::new();
        let mut base_fees_per_gas = Vec::new();
        let mut last_header = None;
        let mut parent_hash = B256::default();

        for i in (0..block_count).rev() {
            let hash = rng.gen();
            let gas_limit: u64 = rng.gen();
            let gas_used: u64 = rng.gen();
            // Note: Generates a u32 to avoid overflows later
            let base_fee_per_gas: Option<u64> = rng.gen::<bool>().then(|| rng.gen::<u32>() as u64);

            let header = Header {
                number: newest_block - i,
                gas_limit,
                gas_used,
                base_fee_per_gas,
                parent_hash,
                ..Default::default()
            };
            last_header = Some(header.clone());
            parent_hash = hash;

            let mut transactions = vec![];
            for _ in 0..100 {
                let random_fee: u128 = rng.gen();

                if let Some(base_fee_per_gas) = header.base_fee_per_gas {
                    let transaction = TransactionSigned {
                        transaction: reth_primitives::Transaction::Eip1559(
                            alloy_consensus::transaction::TxEip1559 {
                                max_priority_fee_per_gas: random_fee,
                                max_fee_per_gas: random_fee + base_fee_per_gas as u128,
                                ..Default::default()
                            },
                        ),
                        ..Default::default()
                    };

                    transactions.push(transaction);
                } else {
                    let transaction = TransactionSigned {
                        transaction: reth_primitives::Transaction::Legacy(Default::default()),
                        ..Default::default()
                    };

                    transactions.push(transaction);
                }
            }

            mock_provider.add_block(
                hash,
                Block { header: header.clone(), body: BlockBody {transactions, ..Default::default()} },
            );
            mock_provider.add_header(hash, header);

            oldest_block.get_or_insert(hash);
            gas_used_ratios.push(gas_used as f64 / gas_limit as f64);
            base_fees_per_gas.push(base_fee_per_gas.map(|fee| fee as u128).unwrap_or_default());
        }

        // Add final base fee (for the next block outside of the request)
        let last_header = last_header.unwrap();
        base_fees_per_gas.push(BaseFeeParams::ethereum().next_block_base_fee(
            last_header.gas_used,
            last_header.gas_limit ,
            last_header.base_fee_per_gas.unwrap_or_default(),
        ) as u128);

        let eth_api = build_test_eth_api(mock_provider);

        (eth_api, base_fees_per_gas, gas_used_ratios)
    }

    /// Invalid block range
    #[tokio::test]
    async fn test_fee_history_empty() {
        let response = <EthApi<_, _, _, _> as EthApiServer<_, _, _>>::fee_history(
            &build_test_eth_api(NoopProvider::default()),
            U64::from(1),
            BlockNumberOrTag::Latest,
            None,
        )
        .await;
        assert!(response.is_err());
        let error_object = response.unwrap_err();
        assert_eq!(error_object.code(), INVALID_PARAMS_CODE);
    }

    #[tokio::test]
    /// Invalid block range (request is before genesis)
    async fn test_fee_history_invalid_block_range_before_genesis() {
        let block_count = 10;
        let newest_block = 1337;
        let oldest_block = None;

        let (eth_api, _, _) =
            prepare_eth_api(newest_block, oldest_block, block_count, MockEthProvider::default());

        let response = <EthApi<_, _, _, _> as EthApiServer<_, _, _>>::fee_history(
            &eth_api,
            U64::from(newest_block + 1),
            newest_block.into(),
            Some(vec![10.0]),
        )
        .await;

        assert!(response.is_err());
        let error_object = response.unwrap_err();
        assert_eq!(error_object.code(), INVALID_PARAMS_CODE);
    }

    #[tokio::test]
    /// Invalid block range (request is in the future)
    async fn test_fee_history_invalid_block_range_in_future() {
        let block_count = 10;
        let newest_block = 1337;
        let oldest_block = None;

        let (eth_api, _, _) =
            prepare_eth_api(newest_block, oldest_block, block_count, MockEthProvider::default());

        let response = <EthApi<_, _, _, _> as EthApiServer<_, _, _>>::fee_history(
            &eth_api,
            U64::from(1),
            (newest_block + 1000).into(),
            Some(vec![10.0]),
        )
        .await;

        assert!(response.is_err());
        let error_object = response.unwrap_err();
        assert_eq!(error_object.code(), INVALID_PARAMS_CODE);
    }

    #[tokio::test]
    /// Requesting no block should result in a default response
    async fn test_fee_history_no_block_requested() {
        let block_count = 10;
        let newest_block = 1337;
        let oldest_block = None;

        let (eth_api, _, _) =
            prepare_eth_api(newest_block, oldest_block, block_count, MockEthProvider::default());

        let response = <EthApi<_, _, _, _> as EthApiServer<_, _, _>>::fee_history(
            &eth_api,
            U64::from(0),
            newest_block.into(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            response,
            alloy_rpc_types_eth::FeeHistory::default(),
            "none: requesting no block should yield a default response"
        );
    }

    #[tokio::test]
    /// Requesting a single block should return 1 block (+ base fee for the next block over)
    async fn test_fee_history_single_block() {
        let block_count = 10;
        let newest_block = 1337;
        let oldest_block = None;

        let (eth_api, base_fees_per_gas, gas_used_ratios) =
            prepare_eth_api(newest_block, oldest_block, block_count, MockEthProvider::default());

        let fee_history =
            eth_api.fee_history(U64::from(1), newest_block.into(), None).await.unwrap();
        assert_eq!(
            fee_history.base_fee_per_gas,
            &base_fees_per_gas[base_fees_per_gas.len() - 2..],
            "one: base fee per gas is incorrect"
        );
        assert_eq!(
            fee_history.base_fee_per_gas.len(),
            2,
            "one: should return base fee of the next block as well"
        );
        assert_eq!(
            &fee_history.gas_used_ratio,
            &gas_used_ratios[gas_used_ratios.len() - 1..],
            "one: gas used ratio is incorrect"
        );
        assert_eq!(fee_history.oldest_block, newest_block, "one: oldest block is incorrect");
        assert!(
            fee_history.reward.is_none(),
            "one: no percentiles were requested, so there should be no rewards result"
        );
    }

    /// Requesting all blocks should be ok
    #[tokio::test]
    async fn test_fee_history_all_blocks() {
        let block_count = 10;
        let newest_block = 1337;
        let oldest_block = None;

        let (eth_api, base_fees_per_gas, gas_used_ratios) =
            prepare_eth_api(newest_block, oldest_block, block_count, MockEthProvider::default());

        let fee_history =
            eth_api.fee_history(U64::from(block_count), newest_block.into(), None).await.unwrap();

        assert_eq!(
            &fee_history.base_fee_per_gas, &base_fees_per_gas,
            "all: base fee per gas is incorrect"
        );
        assert_eq!(
            fee_history.base_fee_per_gas.len() as u64,
            block_count + 1,
            "all: should return base fee of the next block as well"
        );
        assert_eq!(
            &fee_history.gas_used_ratio, &gas_used_ratios,
            "all: gas used ratio is incorrect"
        );
        assert_eq!(
            fee_history.oldest_block,
            newest_block - block_count + 1,
            "all: oldest block is incorrect"
        );
        assert!(
            fee_history.reward.is_none(),
            "all: no percentiles were requested, so there should be no rewards result"
        );
    }
}
