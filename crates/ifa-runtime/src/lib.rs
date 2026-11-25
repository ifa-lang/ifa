//! IFA Runtime: Deterministic zero-GC generational memory allocator, fiber scheduler, and standard library runtime.

pub mod allocator;
pub mod benchmarks;
pub mod blocking;
pub mod collections;
pub mod ffi;
pub mod fiber;
pub mod header;
pub mod io;
pub mod panic;
pub mod reactor;
pub mod session_sync;
pub mod simd_classifier;
pub mod string;
pub mod telemetry;
pub mod wasi;
pub mod zstd_archive;

pub use allocator::{
    call_arena_alloc, call_arena_capacity, call_arena_guard, call_arena_high_water_mark,
    call_arena_mark, call_arena_reset, call_arena_rewind, call_arena_shrink_to_fit,
    call_arena_stats, CallArenaGuard, CallArenaStats, EpochGuard, EpochManager, EpochStats,
    GenArena, GlobalGenAllocator, SizeClassPool, SlabPage, SlabPoolSaturationStats, SlabStatus,
    ThreadLocalCallArena, CALL_ARENA_INITIAL_CAPACITY, DEFAULT_PAGE_CAPACITY, GLOBAL_ALLOCATOR,
};
pub use benchmarks::{
    create_saturated_multipath_snapshot, profile_allocator_engine, run_allocator_multithread_suite,
    run_generational_benchmark_suite, run_issp_failover_benchmark_suite, run_issp_scenario,
    run_simd_capsule_and_classification_benchmark, run_telemetry_streaming_vs_polling_benchmark,
    run_zstd_trace_archive_benchmark, AllocatorEngine, AllocatorThroughputResult, BenchmarkReport,
    BenchmarkResult, IsspBenchmarkScenarioResult, IsspFailoverBenchmarkSuiteReport,
    IsspNetworkProfile, MultithreadBenchmarkSuiteReport, SimdClassificationBenchmarkReport,
    SimdPhaseResult, TelemetryComparativeReport, TelemetryLoadResult, TelemetryTransportKind,
    ZstdTraceArchiveBenchmarkReport,
};
pub use blocking::{
    ifa_rt_blocking_call, ifa_rt_blocking_pool_active_workers, ifa_rt_blocking_pool_capacity,
    ifa_rt_blocking_spawn, BlockingHandle, BlockingPool, ExternBlockingFn, ExternCompletionCb,
    GLOBAL_BLOCKING_POOL,
};
pub use collections::{IfaList, IfaMap};
pub use ffi::*;
pub use fiber::{
    AtomicRingBuffer, Channel, CoroDestroyFn, CoroResumeFn, CoroStatus, FiberId, FiberScheduler,
    FiberState, FiberStepResult, FiberTask, RecvError, SendError, StacklessCoro, TryRecvError,
    TrySendError, GLOBAL_SCHEDULER,
};
pub use header::{
    EpochTransition, GenHeader, GenRef, ARENA_THREAD_LOCAL_CALL, FLAG_ACTIVE, FLAG_ARENA_SCOPED,
    FLAG_EPOCH_1, FLAG_FREE, FLAG_PINNED, FLAG_QUARANTINED, FLAG_READONLY,
};
pub use panic::{
    catch_panic, clear_last_panic, dispatch_panic, get_last_panic, get_last_panic_raw_ptr,
    reset_panic_handler, set_panic_handler, IfaBareMetalStackTrace, IfaPanicKind, IfaPanicRecord,
    PanicHandlerFn, MAX_BARE_METAL_FRAMES, MAX_PANIC_MSG_LEN,
};
pub use reactor::{
    ifa_rt_async_close, ifa_rt_async_io_uring_supported, ifa_rt_async_iocp_supported,
    ifa_rt_async_read, ifa_rt_async_sleep, ifa_rt_async_tcp_accept, ifa_rt_async_tcp_connect,
    ifa_rt_async_tcp_get_nodelay, ifa_rt_async_tcp_get_ttl, ifa_rt_async_tcp_listen,
    ifa_rt_async_tcp_listener_get_ttl, ifa_rt_async_tcp_listener_port,
    ifa_rt_async_tcp_listener_set_ttl, ifa_rt_async_tcp_set_nodelay, ifa_rt_async_tcp_set_ttl,
    ifa_rt_async_udp_bind, ifa_rt_async_udp_connect, ifa_rt_async_udp_get_broadcast,
    ifa_rt_async_udp_get_ttl, ifa_rt_async_udp_port, ifa_rt_async_udp_recv,
    ifa_rt_async_udp_recv_from, ifa_rt_async_udp_send, ifa_rt_async_udp_send_to,
    ifa_rt_async_udp_set_broadcast, ifa_rt_async_udp_set_ttl, ifa_rt_async_write, AsyncReactor,
    AsyncTcpListener, AsyncTcpStream, AsyncTimer, AsyncUdpSocket, IoUringConnector, IocpConnector,
    KernelTimespec, GLOBAL_REACTOR,
};
pub use session_sync::{
    ClusterPsk, FailoverAction, GossipFrame, GossipResult, IsspAdaptiveHeaderCompressor,
    IsspBandwidthEstimate, IsspBbrState, IsspCapsule, IsspCongestionPhase, IsspCongestionState,
    IsspDeliveredPacket, IsspDynamicMultipathRouter, IsspFailoverEvent, IsspFailoverReason,
    IsspFlapDampingConfig, IsspFlapEvent, IsspHeaderCompressionTelemetry, IsspHeaderContextEntry,
    IsspHeartbeatProbe, IsspInterfaceFailoverReport, IsspInterfaceRestoreReport, IsspLedbatState,
    IsspMultipathRoute, IsspMultipathTelemetry, IsspPathMetrics, IsspPathState,
    IsspProbationConfig, IsspProbationState, IsspReintegrationEvent, IsspResequenceStatus,
    IsspResequencingBuffer, IsspResequencingTelemetry, IsspRouteFlapState, IsspRoutingPolicy,
    IsspScheduledPacket, IsspSessionHeader, IsspSubpathCryptoTunnel, IsspSubpathKey,
    IsspSubpathPacket, OpportunisticSecurityLevel, RawGossipError, RejectReason, SecureGossipFrame,
    SecurityError, SecurityPolicy, SessionId, SessionRecord, SessionRegistry, SessionSnapshot,
    SessionTickConfig, SessionTickOutcome, SubpathCryptoTelemetry, SubpathEncryptResult, SyncError,
    SyncTelemetry, GOSSIP_FRAME_SIZE, ISSP_CAPSULE_HEADER_SIZE, ISSP_CAPSULE_MAGIC,
    ISSP_DUMP_HEADER_SIZE, ISSP_DUMP_MAGIC, ISSP_DUMP_VERSION_V1, ISSP_HEARTBEAT_MAGIC,
    ISSP_HEARTBEAT_SIZE, ISSP_MAGIC, ISSP_PKT_FLAG_COMPRESSED, ISSP_PKT_FLAG_ENCRYPTED,
    ISSP_PKT_FLAG_FULL_HEADER, ISSP_SESSION_HEADER_UNCOMPRESSED_SIZE, ISSP_SESSION_MAGIC,
    ISSP_SUBPATH_PACKET_MAGIC, ISSP_VERSION_V1, ISSP_VERSION_V2_ENCRYPTED, MAX_PEER_NODES,
    MAX_SESSIONS, SECURE_GOSSIP_FRAME_SIZE, SNAPSHOT_MAX_AGE,
};
pub use simd_classifier::{
    decode_capsule_header_simd, decode_capsule_headers_batch_simd, decode_capsule_view_simd,
    IsspCapsuleHeader, IsspCapsuleView, IsspClassifiedBatch, IsspPacketPriority,
    IsspSimdPacketClassifier, IsspTelemetryPacketClass, ISSP_FAMILY_PREFIX, ISSP_MESH_LSA_MAGIC,
    ISSP_MIGRATION_MAGIC, ISSP_TELEMETRY_MAGIC, ISSP_TRACE_MAGIC,
};
pub use string::IfaString;
pub use telemetry::{
    snapshot_to_compact_json, supervise_command, ws_build_close_frame, ws_build_text_frame,
    AlertFailoverPolicy, AlertmanagerWebhookAlert, AlertmanagerWebhookPayload, GrpcFrame,
    GrpcFrameError, IsspClusterQuorumConfig, IsspMeshLinkInfo, IsspMeshNodeInfo,
    IsspMeshTopologySnapshot, IsspMultiNodeMeshSynthesizer, IsspMultipathBalancingSnapshot,
    IsspQuorumStatus, IsspSubpathBalancingMetrics, IsspTelemetryHttpHandler, IsspTelemetryServer,
    LatencyHistogram, MiniJsonValue, OtelMultipathBalancingExporter,
    OtelMultipathBalancingGrpcExporter, OtelProtobufMultipathExporter, OtlpGrpcError,
    OtlpGrpcExportResult, PrometheusMultipathBalancingExporter, ProtobufWriter, ResourceAuditScope,
    ResourceUsage, DEFAULT_LATENCY_BUCKETS_SECONDS,
};
pub use wasi::*;
pub use zstd_archive::{
    decode_zstd_stream, encode_zstd_chunk, encode_zstd_chunk_with_stats, IsspCongestionTraceRecord,
    IsspMultipathTelemetryRecord, IsspZstdArchiveTelemetry, IsspZstdMemoryPipeline,
    IsspZstdStreamDecompressor, IsspZstdStreamingPipeline, ZstdArchiveError,
    ISSP_MULTIPATH_TELEMETRY_RECORD_SIZE, ISSP_TRACE_RECORD_SIZE, PHASE_CONGESTION_AVOIDANCE,
    PHASE_DRAIN, PHASE_PROBE_BW, PHASE_PROBE_RTT, PHASE_RECOVERY, PHASE_SLOW_START,
    TRACE_FLAG_CWND_REDUCED, TRACE_FLAG_ECN, TRACE_FLAG_LOSS, TRACE_FLAG_PROBE,
    TRACE_FLAG_RETRANSMIT, TRACE_FLAG_RTT_SURGE, ZSTD_BLOCK_SIZE_MAX, ZSTD_MAGIC,
};
