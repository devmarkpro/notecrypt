/// Explicit allocation, collection, and recursion limits for phase-one readers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeLimits {
    pub max_header_bytes: usize,
    pub max_object_bytes: u64,
    pub max_chunks_per_file: u32,
    pub max_tree_entries: u32,
    pub max_snapshot_parents: u8,
    pub max_name_bytes: u16,
    pub max_head_bytes: u32,
    pub max_manifest_bytes: u32,
    pub max_tree_bytes: u32,
    pub max_snapshot_bytes: u32,
    pub max_local_record_bytes: u32,
    pub max_recovery_slots: u8,
    pub max_aggregate_allocation_bytes: usize,
    pub max_recursion_depth: u8,
}

impl DecodeLimits {
    pub const PHASE_1: Self = Self {
        max_header_bytes: 1_048_576,
        max_object_bytes: 1_099_511_627_776,
        max_chunks_per_file: 1_048_576,
        max_tree_entries: 1_000_000,
        max_snapshot_parents: 2,
        max_name_bytes: 1_024,
        max_head_bytes: 65_536,
        max_manifest_bytes: 67_108_864,
        max_tree_bytes: 268_435_456,
        max_snapshot_bytes: 1_048_576,
        max_local_record_bytes: 65_536,
        max_recovery_slots: 1,
        max_aggregate_allocation_bytes: 268_436_480,
        max_recursion_depth: 16,
    };
}
