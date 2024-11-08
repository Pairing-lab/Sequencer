//! Optimism Node types config.

use std::sync::Arc;

use reth_basic_payload_builder::{BasicPayloadJobGenerator, BasicPayloadJobGeneratorConfig};
use reth_chainspec::{EthChainSpec, Hardforks};
use reth_evm::{execute::BasicBlockExecutorProvider, ConfigureEvm};
use reth_network::{NetworkConfig, NetworkHandle, NetworkManager, PeersInfo};
use reth_node_api::{
    AddOnsContext, EngineValidator, FullNodeComponents, NodeAddOns, NodePrimitives,
};
use reth_node_builder::{
    components::{
        ComponentsBuilder, ConsensusBuilder, ExecutorBuilder, NetworkBuilder,
        PayloadServiceBuilder, PoolBuilder, PoolBuilderConfigOverrides,
    },
    node::{FullNodeTypes, NodeTypes, NodeTypesWithEngine},
    rpc::{EngineValidatorBuilder, RethRpcAddOns, RpcAddOns, RpcHandle},
    BuilderContext, Node, NodeAdapter, NodeComponentsBuilder, PayloadBuilderConfig,
};
use reth_optimism_consensus::OpBeaconConsensus as StradustConsensus;
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_evm::{OpEvmConfig, OpExecutionStrategyFactory};
use reth_optimism_payload_builder::builder::OpPayloadTransactions;
use reth_optimism_rpc::OpEthApi;
use reth_payload_builder::{PayloadBuilderHandle, PayloadBuilderService};
use reth_primitives::{Block, Header, Receipt};
use reth_provider::CanonStateSubscriptions;
use reth_tracing::tracing::{debug, info};
use reth_transaction_pool::{
    blobstore::DiskFileBlobStore, CoinbaseTipOrdering, TransactionPool,
    TransactionValidationTaskExecutor,
};
use reth_trie_db::MerklePatriciaTrie;

use reth_optimism_node::{
    args::RollupArgs,
    engine::OpEngineValidator,
    txpool::{OpTransactionPool, OpTransactionValidator},
    OpEngineTypes,
};

/// Optimism primitive types.
#[derive(Debug)]
pub struct StardustPrimitives;

impl NodePrimitives for StardustPrimitives {
    type Block = Block;
    type Receipt = Receipt;
}

/// Type configuration for a regular Optimism node.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct StardustNode;

impl StardustNode {
    /// Creates a new instance of the Optimism node type.
    /// Returns the components for the given [`RollupArgs`].
    pub fn components<Node>() -> 
    ComponentsBuilder<
        Node,
        StardustPoolBuilder,
        StardustPayloadBuilder,
        StardustNetworkBuilder,
        StardustExecutorBuilder,
        StardustConsensusBuilder,
    >
    where
        Node: FullNodeTypes<
            Types: NodeTypesWithEngine<Engine = OpEngineTypes, ChainSpec = OpChainSpec>,
        >,
    {
        ComponentsBuilder::default()
            .node_types::<Node>()
            .pool(StardustPoolBuilder::default())
            .payload(StardustPayloadBuilder::default())
            .network(StardustNetworkBuilder::default())
            .executor(StardustExecutorBuilder::default())
            .consensus(StardustConsensusBuilder::default())
    }
}

impl<N> Node<N> for StardustNode
where
    N: FullNodeTypes<Types: NodeTypesWithEngine<Engine = OpEngineTypes, ChainSpec = OpChainSpec>>,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        StardustPoolBuilder,
        StardustPayloadBuilder,
        StardustNetworkBuilder,
        StardustExecutorBuilder,
        StardustConsensusBuilder,
    >;

    type AddOns =
        StardustAddOns<NodeAdapter<N, <Self::ComponentsBuilder as NodeComponentsBuilder<N>>::Components>>;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        Self::components()
    }

    fn add_ons(&self) -> Self::AddOns {
        StardustAddOns::default() // TODO:: new 만들기 
    }
}

impl NodeTypes for StardustNode {
    type Primitives = StardustPrimitives;
    type ChainSpec = OpChainSpec;
    type StateCommitment = MerklePatriciaTrie;
}

impl NodeTypesWithEngine for StardustNode {
    type Engine = OpEngineTypes;
}

/// Add-ons w.r.t. optimism.
#[derive(Debug)]
pub struct StardustAddOns<N: FullNodeComponents>(pub RpcAddOns<N, OpEthApi<N>, OpEngineValidatorBuilder>); // Stardust 로 변경할 것 

impl<N: FullNodeComponents> Default for StardustAddOns<N> {
    fn default() -> Self {
        Self::new(None)
    }
}

impl<N: FullNodeComponents> StardustAddOns<N> {
    /// Create a new instance with the given `sequencer_http` URL.
    pub fn new(sequencer_http: Option<String>) -> Self {
        Self(RpcAddOns::new(move |ctx| OpEthApi::new(ctx, sequencer_http), Default::default()))
    }
}

impl<N> NodeAddOns<N> for StardustAddOns<N>
where
    N: FullNodeComponents<Types: NodeTypes<ChainSpec = OpChainSpec>>,
    OpEngineValidator: EngineValidator<<N::Types as NodeTypesWithEngine>::Engine>,
{
    type Handle = RpcHandle<N, OpEthApi<N>>;

    async fn launch_add_ons(
        self,
        ctx: reth_node_api::AddOnsContext<'_, N>,
    ) -> eyre::Result<Self::Handle> {
        self.0.launch_add_ons(ctx).await
    }
}

impl<N> RethRpcAddOns<N> for StardustAddOns<N>
where
    N: FullNodeComponents<Types: NodeTypes<ChainSpec = OpChainSpec>>,
    OpEngineValidator: EngineValidator<<N::Types as NodeTypesWithEngine>::Engine>,
{
    type EthApi = OpEthApi<N>;

    fn hooks_mut(&mut self) -> &mut reth_node_builder::rpc::RpcHooks<N, Self::EthApi> {
        self.0.hooks_mut()
    }
}

/// A regular optimism evm and executor builder.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct StardustExecutorBuilder;

impl<Node> ExecutorBuilder<Node> for StardustExecutorBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = OpChainSpec>>,
{
    type EVM = OpEvmConfig;
    type Executor = BasicBlockExecutorProvider<OpExecutionStrategyFactory>;

    async fn build_evm(
        self,
        ctx: &BuilderContext<Node>,
    ) -> eyre::Result<(Self::EVM, Self::Executor)> {
        let evm_config = OpEvmConfig::new(ctx.chain_spec());
        let strategy_factory =
            OpExecutionStrategyFactory::new(ctx.chain_spec(), evm_config.clone());
        let executor = BasicBlockExecutorProvider::new(strategy_factory);

        Ok((evm_config, executor))
    }
}

/// A basic optimism transaction pool.
///
/// This contains various settings that can be configured and take precedence over the node's
/// config.
#[derive(Debug, Default, Clone)]
pub struct StardustPoolBuilder {
    /// Enforced overrides that are applied to the pool config.
    pub pool_config_overrides: PoolBuilderConfigOverrides,
}

impl<Node> PoolBuilder<Node> for StardustPoolBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = OpChainSpec>>,
{
    type Pool = OpTransactionPool<Node::Provider, DiskFileBlobStore>;

    async fn build_pool(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Pool> {
        let Self { pool_config_overrides } = self;
        let data_dir = ctx.config().datadir();
        let blob_store = DiskFileBlobStore::open(data_dir.blobstore(), Default::default())?;

        let validator = TransactionValidationTaskExecutor::eth_builder(Arc::new(
            ctx.chain_spec().inner.clone(),
        ))
        .with_head_timestamp(ctx.head().timestamp)
        .kzg_settings(ctx.kzg_settings()?)
        .with_additional_tasks(
            pool_config_overrides
                .additional_validation_tasks
                .unwrap_or_else(|| ctx.config().txpool.additional_validation_tasks),
        )
        .build_with_tasks(ctx.provider().clone(), ctx.task_executor().clone(), blob_store.clone())
        .map(|validator| {
            OpTransactionValidator::new(validator)
                // In --dev mode we can't require gas fees because we're unable to decode
                // the L1 block info
                .require_l1_data_gas_fee(!ctx.config().dev.dev)
        });

        let transaction_pool = reth_transaction_pool::Pool::new(
            validator,
            CoinbaseTipOrdering::default(),
            blob_store,
            pool_config_overrides.apply(ctx.pool_config()),
        );
        info!(target: "reth::cli", "Transaction pool initialized");
        let transactions_path = data_dir.txpool_transactions();

        // spawn txpool maintenance task
        {
            let pool = transaction_pool.clone();
            let chain_events = ctx.provider().canonical_state_stream();
            let client = ctx.provider().clone();
            let transactions_backup_config =
                reth_transaction_pool::maintain::LocalTransactionBackupConfig::with_local_txs_backup(transactions_path);

            ctx.task_executor().spawn_critical_with_graceful_shutdown_signal(
                "local transactions backup task",
                |shutdown| {
                    reth_transaction_pool::maintain::backup_local_transactions_task(
                        shutdown,
                        pool.clone(),
                        transactions_backup_config,
                    )
                },
            );

            // spawn the maintenance task
            ctx.task_executor().spawn_critical(
                "txpool maintenance task",
                reth_transaction_pool::maintain::maintain_transaction_pool_future(
                    client,
                    pool,
                    chain_events,
                    ctx.task_executor().clone(),
                    Default::default(),
                ),
            );
            debug!(target: "reth::cli", "Spawned txpool maintenance task");
        }

        Ok(transaction_pool)
    }
}

/// A basic optimism payload service builder
#[derive(Debug, Default, Clone)]
pub struct StardustPayloadBuilder<Txs = ()> {
    /// By default the pending block equals the latest block
    /// to save resources and not leak txs from the tx-pool,
    /// this flag enables computing of the pending block
    /// from the tx-pool instead.
    ///
    /// If `compute_pending_block` is not enabled, the payload builder
    /// will use the payload attributes from the latest block. Note
    /// that this flag is not yet functional.
    pub compute_pending_block: bool,
    /// The type responsible for yielding the best transactions for the payload if mempool
    /// transactions are allowed.
    pub best_transactions: Txs,
}

impl StardustPayloadBuilder {
    /// Create a new instance with the given `compute_pending_block` flag.
    pub const fn new(compute_pending_block: bool) -> Self {
        Self { compute_pending_block, best_transactions: () }
    }
}

impl<Txs> StardustPayloadBuilder<Txs>
where
    Txs: OpPayloadTransactions,
{
    /// Configures the type responsible for yielding the transactions that should be included in the
    /// payload.
    pub fn with_transactions<T: OpPayloadTransactions>(
        self,
        best_transactions: T,
    ) -> StardustPayloadBuilder<T> {
        let Self { compute_pending_block, .. } = self;
        StardustPayloadBuilder { compute_pending_block, best_transactions }
    }

    /// A helper method to initialize [`PayloadBuilderService`] with the given EVM config.
    pub fn spawn<Node, Evm, Pool>(
        self,
        evm_config: Evm,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<PayloadBuilderHandle<OpEngineTypes>>
    where
        Node: FullNodeTypes<
            Types: NodeTypesWithEngine<Engine = OpEngineTypes, ChainSpec = OpChainSpec>,
        >,
        Pool: TransactionPool + Unpin + 'static,
        Evm: ConfigureEvm<Header = Header>,
    {
        let payload_builder = reth_optimism_payload_builder::OpPayloadBuilder::new(evm_config)
            .with_transactions(self.best_transactions)
            .set_compute_pending_block(self.compute_pending_block);
        let conf = ctx.payload_builder_config();

        let payload_job_config = BasicPayloadJobGeneratorConfig::default()
            .interval(conf.interval())
            .deadline(conf.deadline())
            .max_payload_tasks(conf.max_payload_tasks())
            // no extradata for OP
            .extradata(Default::default());

        let payload_generator = BasicPayloadJobGenerator::with_builder(
            ctx.provider().clone(),
            pool,
            ctx.task_executor().clone(),
            payload_job_config,
            payload_builder,
        );
        let (payload_service, payload_builder) =
            PayloadBuilderService::new(payload_generator, ctx.provider().canonical_state_stream());

        ctx.task_executor().spawn_critical("payload builder service", Box::pin(payload_service));

        Ok(payload_builder)
    }
}

impl<Node, Pool, Txs> PayloadServiceBuilder<Node, Pool> for StardustPayloadBuilder<Txs>
where
    Node:
        FullNodeTypes<Types: NodeTypesWithEngine<Engine = OpEngineTypes, ChainSpec = OpChainSpec>>,
    Pool: TransactionPool + Unpin + 'static,
    Txs: OpPayloadTransactions,
{
    async fn spawn_payload_service(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<PayloadBuilderHandle<OpEngineTypes>> {
        self.spawn(OpEvmConfig::new(ctx.chain_spec()), ctx, pool)
    }
}

/// A basic optimism network builder.
#[derive(Debug, Default, Clone)]
pub struct StardustNetworkBuilder {
    /// Disable transaction pool gossip
    pub disable_txpool_gossip: bool,
    /// Disable discovery v4
    pub disable_discovery_v4: bool,
}

impl StardustNetworkBuilder {
    /// Returns the [`NetworkConfig`] that contains the settings to launch the p2p network.
    ///
    /// This applies the configured [`OpNetworkBuilder`] settings.
    pub fn network_config<Node>(
        &self,
        ctx: &BuilderContext<Node>,
    ) -> eyre::Result<NetworkConfig<<Node as FullNodeTypes>::Provider>>
    where
        Node: FullNodeTypes<Types: NodeTypes<ChainSpec: Hardforks>>,
    {
        let Self { disable_txpool_gossip, disable_discovery_v4 } = self.clone();
        let args = &ctx.config().network;
        let network_builder = ctx
            .network_config_builder()?
            // apply discovery settings
            .apply(|mut builder| {
                let rlpx_socket = (args.addr, args.port).into();
                if disable_discovery_v4 || args.discovery.disable_discovery {
                    builder = builder.disable_discv4_discovery();
                }
                if !args.discovery.disable_discovery {
                    builder = builder.discovery_v5(
                        args.discovery.discovery_v5_builder(
                            rlpx_socket,
                            ctx.config()
                                .network
                                .resolved_bootnodes()
                                .or_else(|| ctx.chain_spec().bootnodes())
                                .unwrap_or_default(),
                        ),
                    );
                }

                builder
            });

        let mut network_config = ctx.build_network_config(network_builder);

        // When `sequencer_endpoint` is configured, the node will forward all transactions to a
        // Sequencer node for execution and inclusion on L1, and disable its own txpool
        // gossip to prevent other parties in the network from learning about them.
        network_config.tx_gossip_disabled = disable_txpool_gossip;

        Ok(network_config)
    }
}

impl<Node, Pool> NetworkBuilder<Node, Pool> for StardustNetworkBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = OpChainSpec>>,
    Pool: TransactionPool + Unpin + 'static,
{
    async fn build_network(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<NetworkHandle> {
        let network_config = self.network_config(ctx)?;
        let network = NetworkManager::builder(network_config).await?;
        let handle = ctx.start_network(network, pool);
        info!(target: "reth::cli", enode=%handle.local_node_record(), "P2P networking initialized");

        Ok(handle)
    }
}

/// A basic optimism consensus builder.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct StardustConsensusBuilder;

impl<Node> ConsensusBuilder<Node> for StardustConsensusBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = OpChainSpec>>,
{
    type Consensus = Arc<dyn reth_consensus::Consensus>;  

    async fn build_consensus(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Consensus> {
        Ok(Arc::new(StradustConsensus::new(ctx.chain_spec())))
    }
}

/// Builder for [`OpEngineValidator`].
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct OpEngineValidatorBuilder;

impl<Node, Types> EngineValidatorBuilder<Node> for OpEngineValidatorBuilder
where
    Types: NodeTypesWithEngine<ChainSpec = OpChainSpec>,
    Node: FullNodeComponents<Types = Types>,
    OpEngineValidator: EngineValidator<Types::Engine>,
{
    type Validator = OpEngineValidator;

    async fn build(self, ctx: &AddOnsContext<'_, Node>) -> eyre::Result<Self::Validator> {
        Ok(OpEngineValidator::new(ctx.config.chain.clone()))
    }
}

