use crate::{BlockReaderIdExt, BlockReader, ChainSpecProvider, ChainSpec
,EvmEnvProvider, StateProviderFactory , EthApi, TestPool, STARDUSTTESTNetwork,
EthEvmConfig, EthStateCache , FeeHistoryCache, FeeHistoryCacheConfig , GasPriceOracle
, DEFAULT_ETH_PROOF_WINDOW, DEFAULT_PROOF_PERMITS , DEFAULT_MAX_SIMULATE_BLOCKS
, BlockingTaskPool, testing_pool};

pub fn build_dummy_eth_api<
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
    ) -> EthApi<P, TestPool, STARDUSTTESTNetwork, EthEvmConfig> {
        let evm_config = EthEvmConfig::new(provider.chain_spec());
        let cache = EthStateCache::spawn(provider.clone(), Default::default(), evm_config.clone());
        let fee_history_cache =
            FeeHistoryCache::new(cache.clone(), FeeHistoryCacheConfig::default());

        let gas_cap = provider.chain_spec().max_gas_limit;
        EthApi::new(
            provider.clone(),
            testing_pool(),
            STARDUSTTESTNetwork::default(),
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