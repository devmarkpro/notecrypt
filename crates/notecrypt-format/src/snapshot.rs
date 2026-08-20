use minicbor::{Decoder, Encoder};
use zeroize::Zeroize;

use crate::object::{
    CanonicalCompareWriter, CountingWriter, check_input_bound, copy_bounded, finish, fixed_bytes,
    output_buffer, require_array, require_depth,
};
use crate::{DecodeLimits, FORMAT_VERSION_V1, FormatError};

#[derive(PartialEq, Eq)]
pub struct RevisionLocator {
    revision_id: [u8; 32],
    manifest_object_id: [u8; 32],
}

impl RevisionLocator {
    #[must_use]
    pub const fn new(revision_id: [u8; 32], manifest_object_id: [u8; 32]) -> Self {
        Self {
            revision_id,
            manifest_object_id,
        }
    }

    #[must_use]
    pub const fn revision_id(&self) -> &[u8; 32] {
        &self.revision_id
    }

    #[must_use]
    pub const fn manifest_object_id(&self) -> &[u8; 32] {
        &self.manifest_object_id
    }

    #[must_use]
    pub const fn into_parts(self) -> ([u8; 32], [u8; 32]) {
        (self.revision_id, self.manifest_object_id)
    }
}

#[derive(PartialEq, Eq)]
pub struct SnapshotParentLocator {
    snapshot_id: [u8; 32],
    snapshot_object_id: [u8; 32],
}

impl SnapshotParentLocator {
    #[must_use]
    pub const fn new(snapshot_id: [u8; 32], snapshot_object_id: [u8; 32]) -> Self {
        Self {
            snapshot_id,
            snapshot_object_id,
        }
    }

    #[must_use]
    pub const fn snapshot_id(&self) -> &[u8; 32] {
        &self.snapshot_id
    }

    #[must_use]
    pub const fn snapshot_object_id(&self) -> &[u8; 32] {
        &self.snapshot_object_id
    }

    #[must_use]
    pub const fn into_parts(self) -> ([u8; 32], [u8; 32]) {
        (self.snapshot_id, self.snapshot_object_id)
    }
}

#[derive(PartialEq, Eq)]
pub enum TreeEntry {
    Root {
        id: [u8; 16],
    },
    File {
        id: [u8; 16],
        parent: [u8; 16],
        name: String,
        locator: RevisionLocator,
    },
    Directory {
        id: [u8; 16],
        parent: [u8; 16],
        name: String,
    },
    Tombstone {
        id: [u8; 16],
        parent: [u8; 16],
        name: String,
        deleted_in: [u8; 32],
        prior_kind: PriorEntryKind,
        last_revision: Option<RevisionLocator>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PriorEntryKind {
    File = 1,
    Directory = 2,
}
impl TryFrom<u8> for PriorEntryKind {
    type Error = FormatError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(Self::File),
            2 => Ok(Self::Directory),
            _ => Err(FormatError::Malformed),
        }
    }
}

impl TreeEntry {
    #[must_use]
    pub const fn root(id: [u8; 16]) -> Self {
        Self::Root { id }
    }
    pub fn file(
        id: [u8; 16],
        parent: [u8; 16],
        name: &str,
        locator: RevisionLocator,
        limits: &DecodeLimits,
    ) -> Result<Self, FormatError> {
        validate_name(name, limits)?;
        Ok(Self::File {
            id,
            parent,
            name: copy_owned_name(name)?,
            locator,
        })
    }
    pub fn directory(
        id: [u8; 16],
        parent: [u8; 16],
        name: &str,
        limits: &DecodeLimits,
    ) -> Result<Self, FormatError> {
        validate_name(name, limits)?;
        Ok(Self::Directory {
            id,
            parent,
            name: copy_owned_name(name)?,
        })
    }
    pub fn tombstone(
        id: [u8; 16],
        parent: [u8; 16],
        name: &str,
        deleted_in: [u8; 32],
        prior_kind: PriorEntryKind,
        last_revision: Option<RevisionLocator>,
        limits: &DecodeLimits,
    ) -> Result<Self, FormatError> {
        validate_name(name, limits)?;
        if (prior_kind == PriorEntryKind::File) != last_revision.is_some() {
            return Err(FormatError::Malformed);
        }
        Ok(Self::Tombstone {
            id,
            parent,
            name: copy_owned_name(name)?,
            deleted_in,
            prior_kind,
            last_revision,
        })
    }
    #[must_use]
    pub const fn id(&self) -> &[u8; 16] {
        match self {
            Self::Root { id }
            | Self::File { id, .. }
            | Self::Directory { id, .. }
            | Self::Tombstone { id, .. } => id,
        }
    }
}
impl Drop for TreeEntry {
    fn drop(&mut self) {
        match self {
            Self::File { name, .. }
            | Self::Directory { name, .. }
            | Self::Tombstone { name, .. } => name.zeroize(),
            Self::Root { .. } => {}
        }
    }
}

#[derive(PartialEq, Eq)]
pub struct LogicalTree {
    root: [u8; 16],
    entries: Vec<TreeEntry>,
}

impl LogicalTree {
    pub fn try_new(
        root: [u8; 16],
        mut entries: Vec<TreeEntry>,
        limits: &DecodeLimits,
    ) -> Result<Self, FormatError> {
        if entries.is_empty()
            || entries.len()
                > usize::try_from(limits.max_tree_entries).map_err(|_| FormatError::Overflow)?
        {
            return Err(FormatError::LimitExceeded);
        }
        entries.sort_unstable_by(|a, b| a.id().cmp(b.id()));
        Self::try_from_sorted(root, entries)
    }
    fn try_from_sorted(root: [u8; 16], entries: Vec<TreeEntry>) -> Result<Self, FormatError> {
        let mut roots = 0;
        for entry in &entries {
            if let TreeEntry::Root { id } = entry {
                roots += 1;
                if id != &root {
                    return Err(FormatError::Malformed);
                }
            }
        }
        if roots != 1 || entries.windows(2).any(|pair| pair[0].id() >= pair[1].id()) {
            return Err(FormatError::Malformed);
        }
        Ok(Self { root, entries })
    }
    #[must_use]
    pub const fn root(&self) -> &[u8; 16] {
        &self.root
    }
    #[must_use]
    pub fn entries(&self) -> &[TreeEntry] {
        &self.entries
    }
    #[must_use]
    pub fn into_parts(mut self) -> ([u8; 16], Vec<TreeEntry>) {
        (self.root, std::mem::take(&mut self.entries))
    }
}

pub fn encode_tree(value: &LogicalTree) -> Result<Vec<u8>, FormatError> {
    let mut counter = CountingWriter::default();
    encode_tree_to(&mut Encoder::new(&mut counter), value)?;
    let capacity = counter.length()?;
    let mut encoder = Encoder::new(output_buffer(
        capacity,
        usize::try_from(DecodeLimits::PHASE_1.max_tree_bytes).map_err(|_| FormatError::Overflow)?,
    )?);
    encode_tree_to(&mut encoder, value)?;
    let bytes = encoder.into_writer();
    if bytes.len()
        > usize::try_from(DecodeLimits::PHASE_1.max_tree_bytes)
            .map_err(|_| FormatError::Overflow)?
    {
        return Err(FormatError::LimitExceeded);
    }
    Ok(bytes)
}

pub fn decode_tree(bytes: &[u8], limits: &DecodeLimits) -> Result<LogicalTree, FormatError> {
    require_depth(limits, 4)?;
    check_input_bound(bytes, u64::from(limits.max_tree_bytes))?;
    let mut decoder = Decoder::new(bytes);
    require_array(&mut decoder, 3)?;
    require_v1(decoder.u16()?)?;
    let root = fixed_bytes::<16>(decoder.bytes()?)?;
    let count = decoder.array()?.ok_or(FormatError::NonCanonical)?;
    if count == 0 || count > u64::from(limits.max_tree_entries) {
        return Err(FormatError::LimitExceeded);
    }
    let count = usize::try_from(count).map_err(|_| FormatError::Overflow)?;
    let base = count
        .checked_mul(std::mem::size_of::<TreeEntry>())
        .ok_or(FormatError::Overflow)?;
    if base > limits.max_aggregate_allocation_bytes {
        return Err(FormatError::LimitExceeded);
    }
    let mut allocation = base;
    let mut entries: Vec<TreeEntry> = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|_| FormatError::AllocationFailed)?;
    for _ in 0..count {
        let entry = decode_tree_entry(&mut decoder, limits, &mut allocation)?;
        if entries
            .last()
            .is_some_and(|previous| previous.id() >= entry.id())
        {
            return Err(FormatError::NonCanonical);
        }
        entries.push(entry);
    }
    finish(&decoder, bytes)?;
    let value = LogicalTree::try_from_sorted(root, entries)?;
    let mut writer = CanonicalCompareWriter::new(bytes);
    encode_tree_to(&mut Encoder::new(&mut writer), &value)?;
    writer.finish()?;
    Ok(value)
}

fn encode_tree_to<W: minicbor::encode::Write>(
    encoder: &mut Encoder<W>,
    value: &LogicalTree,
) -> Result<(), FormatError> {
    encoder
        .array(3)?
        .u16(FORMAT_VERSION_V1)?
        .bytes(&value.root)?
        .array(u64::try_from(value.entries.len()).map_err(|_| FormatError::Overflow)?)?;
    for entry in &value.entries {
        encode_tree_entry(encoder, entry)?;
    }
    Ok(())
}
fn encode_tree_entry<W: minicbor::encode::Write>(
    encoder: &mut Encoder<W>,
    entry: &TreeEntry,
) -> Result<(), FormatError> {
    match entry {
        TreeEntry::Root { id } => {
            encoder.array(2)?.u8(0)?.bytes(id)?;
        }
        TreeEntry::File {
            id,
            parent,
            name,
            locator,
        } => {
            encoder
                .array(5)?
                .u8(1)?
                .bytes(id)?
                .bytes(parent)?
                .str(name)?
                .array(2)?
                .bytes(locator.revision_id())?
                .bytes(locator.manifest_object_id())?;
        }
        TreeEntry::Directory { id, parent, name } => {
            encoder
                .array(4)?
                .u8(2)?
                .bytes(id)?
                .bytes(parent)?
                .str(name)?;
        }
        TreeEntry::Tombstone {
            id,
            parent,
            name,
            deleted_in,
            prior_kind,
            last_revision,
        } => {
            encoder
                .array(7)?
                .u8(3)?
                .bytes(id)?
                .bytes(parent)?
                .str(name)?
                .bytes(deleted_in)?
                .u8(*prior_kind as u8)?;
            if let Some(locator) = last_revision {
                encoder
                    .array(2)?
                    .bytes(locator.revision_id())?
                    .bytes(locator.manifest_object_id())?;
            } else {
                encoder.null()?;
            }
        }
    }
    Ok(())
}

fn decode_tree_entry(
    decoder: &mut Decoder<'_>,
    limits: &DecodeLimits,
    allocation: &mut usize,
) -> Result<TreeEntry, FormatError> {
    let length = decoder.array()?.ok_or(FormatError::NonCanonical)?;
    let kind = decoder.u8()?;
    let expected = match kind {
        0 => 2,
        1 => 5,
        2 => 4,
        3 => 7,
        _ => return Err(FormatError::Malformed),
    };
    if length != expected {
        return Err(FormatError::Malformed);
    }
    let id = fixed_bytes::<16>(decoder.bytes()?)?;
    match kind {
        0 => Ok(TreeEntry::root(id)),
        1 => {
            let parent = fixed_bytes::<16>(decoder.bytes()?)?;
            let name = decoder.str()?;
            require_array(decoder, 2)?;
            let revision_id = fixed_bytes::<32>(decoder.bytes()?)?;
            let manifest_object_id = fixed_bytes::<32>(decoder.bytes()?)?;
            Ok(TreeEntry::File {
                id,
                parent,
                name: copy_name(name, limits, allocation)?,
                locator: RevisionLocator::new(revision_id, manifest_object_id),
            })
        }
        2 => {
            let parent = fixed_bytes::<16>(decoder.bytes()?)?;
            let name = copy_name(decoder.str()?, limits, allocation)?;
            Ok(TreeEntry::Directory { id, parent, name })
        }
        3 => {
            let parent = fixed_bytes::<16>(decoder.bytes()?)?;
            let name = decoder.str()?;
            let deleted_in = fixed_bytes::<32>(decoder.bytes()?)?;
            let prior_kind = PriorEntryKind::try_from(decoder.u8()?)?;
            let last_revision = if decoder.datatype()? == minicbor::data::Type::Null {
                decoder.null()?;
                None
            } else {
                require_array(decoder, 2)?;
                Some(RevisionLocator::new(
                    fixed_bytes::<32>(decoder.bytes()?)?,
                    fixed_bytes::<32>(decoder.bytes()?)?,
                ))
            };
            if (prior_kind == PriorEntryKind::File) != last_revision.is_some() {
                return Err(FormatError::Malformed);
            }
            Ok(TreeEntry::Tombstone {
                id,
                parent,
                name: copy_name(name, limits, allocation)?,
                deleted_in,
                prior_kind,
                last_revision,
            })
        }
        _ => unreachable!(),
    }
}

fn copy_name(
    value: &str,
    limits: &DecodeLimits,
    allocation: &mut usize,
) -> Result<String, FormatError> {
    validate_name(value, limits)?;
    *allocation = allocation
        .checked_add(value.len())
        .ok_or(FormatError::Overflow)?;
    if *allocation > limits.max_aggregate_allocation_bytes {
        return Err(FormatError::LimitExceeded);
    }
    let mut owned = String::new();
    owned
        .try_reserve_exact(value.len())
        .map_err(|_| FormatError::AllocationFailed)?;
    owned.push_str(value);
    Ok(owned)
}

fn validate_name(name: &str, limits: &DecodeLimits) -> Result<(), FormatError> {
    if name.is_empty() || name.len() > usize::from(limits.max_name_bytes) || name.contains('\0') {
        Err(FormatError::LimitExceeded)
    } else {
        Ok(())
    }
}

fn copy_owned_name(name: &str) -> Result<String, FormatError> {
    let mut owned = String::new();
    owned
        .try_reserve_exact(name.len())
        .map_err(|_| FormatError::AllocationFailed)?;
    owned.push_str(name);
    Ok(owned)
}

#[derive(PartialEq, Eq)]
pub struct SnapshotPayload {
    snapshot_id: [u8; 32],
    parents: Vec<SnapshotParentLocator>,
    tree_object_id: [u8; 32],
    device_id: [u8; 16],
    device_label: String,
}

impl SnapshotPayload {
    pub fn try_new(
        snapshot_id: [u8; 32],
        mut parents: Vec<SnapshotParentLocator>,
        tree_object_id: [u8; 32],
        device_id: [u8; 16],
        device_label: &str,
        limits: &DecodeLimits,
    ) -> Result<Self, FormatError> {
        let parent_bytes = parents
            .len()
            .checked_mul(std::mem::size_of::<SnapshotParentLocator>())
            .ok_or(FormatError::Overflow)?;
        let aggregate = parent_bytes
            .checked_add(device_label.len())
            .ok_or(FormatError::Overflow)?;
        if parents.len() > usize::from(limits.max_snapshot_parents)
            || device_label.is_empty()
            || device_label.len() > usize::from(limits.max_name_bytes)
            || aggregate > limits.max_aggregate_allocation_bytes
        {
            return Err(FormatError::LimitExceeded);
        }
        parents.sort_unstable_by(|left, right| {
            left.snapshot_id
                .cmp(&right.snapshot_id)
                .then_with(|| left.snapshot_object_id.cmp(&right.snapshot_object_id))
        });
        if parents
            .windows(2)
            .any(|w| w[0].snapshot_id == w[1].snapshot_id)
            || parents.iter().enumerate().any(|(index, parent)| {
                parents[index + 1..]
                    .iter()
                    .any(|other| parent.snapshot_object_id == other.snapshot_object_id)
            })
        {
            return Err(FormatError::Malformed);
        }
        let mut label = String::new();
        label
            .try_reserve_exact(device_label.len())
            .map_err(|_| FormatError::AllocationFailed)?;
        label.push_str(device_label);
        Ok(Self {
            snapshot_id,
            parents,
            tree_object_id,
            device_id,
            device_label: label,
        })
    }
    #[must_use]
    pub const fn snapshot_id(&self) -> &[u8; 32] {
        &self.snapshot_id
    }
    #[must_use]
    pub fn parents(&self) -> &[SnapshotParentLocator] {
        &self.parents
    }
    #[must_use]
    pub const fn tree_object_id(&self) -> &[u8; 32] {
        &self.tree_object_id
    }
    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        mut self,
    ) -> (
        [u8; 32],
        Vec<SnapshotParentLocator>,
        [u8; 32],
        [u8; 16],
        String,
    ) {
        (
            self.snapshot_id,
            std::mem::take(&mut self.parents),
            self.tree_object_id,
            self.device_id,
            std::mem::take(&mut self.device_label),
        )
    }
}
impl Drop for SnapshotPayload {
    fn drop(&mut self) {
        self.device_label.zeroize();
    }
}

pub fn encode_snapshot_payload(value: &SnapshotPayload) -> Result<Vec<u8>, FormatError> {
    let mut counter = CountingWriter::default();
    encode_snapshot_payload_to(&mut Encoder::new(&mut counter), value)?;
    let mut encoder = Encoder::new(output_buffer(
        counter.length()?,
        usize::try_from(DecodeLimits::PHASE_1.max_snapshot_bytes)
            .map_err(|_| FormatError::Overflow)?,
    )?);
    encode_snapshot_payload_to(&mut encoder, value)?;
    Ok(encoder.into_writer())
}
fn encode_snapshot_payload_to<W: minicbor::encode::Write>(
    encoder: &mut Encoder<W>,
    value: &SnapshotPayload,
) -> Result<(), FormatError> {
    encoder
        .array(6)?
        .u16(FORMAT_VERSION_V1)?
        .bytes(&value.snapshot_id)?
        .array(u64::try_from(value.parents.len()).map_err(|_| FormatError::Overflow)?)?;
    for parent in &value.parents {
        encoder
            .array(2)?
            .bytes(parent.snapshot_id())?
            .bytes(parent.snapshot_object_id())?;
    }
    encoder
        .bytes(&value.tree_object_id)?
        .bytes(&value.device_id)?
        .str(&value.device_label)?;
    Ok(())
}

pub fn decode_snapshot_payload(
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<SnapshotPayload, FormatError> {
    require_depth(limits, 4)?;
    check_input_bound(bytes, u64::from(limits.max_snapshot_bytes))?;
    let mut d = Decoder::new(bytes);
    require_array(&mut d, 6)?;
    require_v1(d.u16()?)?;
    let id = fixed_bytes::<32>(d.bytes()?)?;
    let count = d.array()?.ok_or(FormatError::NonCanonical)?;
    if count > u64::from(limits.max_snapshot_parents) {
        return Err(FormatError::LimitExceeded);
    }
    let count = usize::try_from(count).map_err(|_| FormatError::Overflow)?;
    let mut parents = Vec::new();
    parents
        .try_reserve_exact(count)
        .map_err(|_| FormatError::AllocationFailed)?;
    for _ in 0..count {
        require_array(&mut d, 2)?;
        parents.push(SnapshotParentLocator::new(
            fixed_bytes::<32>(d.bytes()?)?,
            fixed_bytes::<32>(d.bytes()?)?,
        ));
    }
    let tree = fixed_bytes::<32>(d.bytes()?)?;
    let device = fixed_bytes::<16>(d.bytes()?)?;
    let label = d.str()?;
    finish(&d, bytes)?;
    let value = SnapshotPayload::try_new(id, parents, tree, device, label, limits)?;
    let mut writer = CanonicalCompareWriter::new(bytes);
    encode_snapshot_payload_to(&mut Encoder::new(&mut writer), &value)?;
    writer.finish()?;
    Ok(value)
}

#[derive(PartialEq, Eq)]
pub struct HeadPayload {
    snapshot_id: [u8; 32],
    snapshot_object_id: [u8; 32],
    tree_object_id: [u8; 32],
}
impl HeadPayload {
    #[must_use]
    pub const fn new(
        snapshot_id: [u8; 32],
        snapshot_object_id: [u8; 32],
        tree_object_id: [u8; 32],
    ) -> Self {
        Self {
            snapshot_id,
            snapshot_object_id,
            tree_object_id,
        }
    }
    #[must_use]
    pub const fn snapshot_id(&self) -> &[u8; 32] {
        &self.snapshot_id
    }
    #[must_use]
    pub const fn snapshot_object_id(&self) -> &[u8; 32] {
        &self.snapshot_object_id
    }
    #[must_use]
    pub const fn tree_object_id(&self) -> &[u8; 32] {
        &self.tree_object_id
    }
}
pub fn encode_head_payload(v: &HeadPayload) -> Result<Vec<u8>, FormatError> {
    let mut counter = CountingWriter::default();
    encode_head_payload_to(&mut Encoder::new(&mut counter), v)?;
    let mut e = Encoder::new(output_buffer(counter.length()?, 1024)?);
    encode_head_payload_to(&mut e, v)?;
    Ok(e.into_writer())
}
fn encode_head_payload_to<W: minicbor::encode::Write>(
    e: &mut Encoder<W>,
    v: &HeadPayload,
) -> Result<(), FormatError> {
    e.array(4)?
        .u16(FORMAT_VERSION_V1)?
        .bytes(&v.snapshot_id)?
        .bytes(&v.snapshot_object_id)?
        .bytes(&v.tree_object_id)?;
    Ok(())
}
pub fn decode_head_payload(
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<HeadPayload, FormatError> {
    require_depth(limits, 1)?;
    check_input_bound(bytes, 1024)?;
    let mut d = Decoder::new(bytes);
    require_array(&mut d, 4)?;
    require_v1(d.u16()?)?;
    let v = HeadPayload::new(
        fixed_bytes::<32>(d.bytes()?)?,
        fixed_bytes::<32>(d.bytes()?)?,
        fixed_bytes::<32>(d.bytes()?)?,
    );
    finish(&d, bytes)?;
    let mut writer = CanonicalCompareWriter::new(bytes);
    encode_head_payload_to(&mut Encoder::new(&mut writer), &v)?;
    writer.finish()?;
    Ok(v)
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LocalRecordType {
    TrustedHead = 1,
    TrustedRemote = 2,
    BackendCopy = 3,
    Cleanup = 4,
    DeviceSlot = 5,
    Journal = 6,
    VaultAvailability = 7,
}
impl TryFrom<u8> for LocalRecordType {
    type Error = FormatError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(Self::TrustedHead),
            2 => Ok(Self::TrustedRemote),
            3 => Ok(Self::BackendCopy),
            4 => Ok(Self::Cleanup),
            5 => Ok(Self::DeviceSlot),
            6 => Ok(Self::Journal),
            7 => Ok(Self::VaultAvailability),
            _ => Err(FormatError::Malformed),
        }
    }
}

#[derive(PartialEq, Eq)]
pub struct LocalStatePayload {
    record_type: LocalRecordType,
    record_id: [u8; 32],
    payload: Vec<u8>,
}
impl LocalStatePayload {
    pub fn try_new(
        record_type: LocalRecordType,
        record_id: [u8; 32],
        mut payload: Vec<u8>,
        limits: &DecodeLimits,
    ) -> Result<Self, FormatError> {
        let maximum = usize::try_from(limits.max_local_record_bytes)
            .map_err(|_| FormatError::Overflow)?
            .checked_sub(256)
            .ok_or(FormatError::LimitExceeded)?;
        if payload.len() > maximum || payload.len() > limits.max_aggregate_allocation_bytes {
            payload.zeroize();
            return Err(FormatError::LimitExceeded);
        }
        Ok(Self {
            record_type,
            record_id,
            payload,
        })
    }
    #[must_use]
    pub fn into_parts(mut self) -> (LocalRecordType, [u8; 32], Vec<u8>) {
        (
            self.record_type,
            self.record_id,
            std::mem::take(&mut self.payload),
        )
    }
}
impl Drop for LocalStatePayload {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}
pub fn encode_local_state_payload(v: &LocalStatePayload) -> Result<Vec<u8>, FormatError> {
    let mut counter = CountingWriter::default();
    encode_local_state_payload_to(&mut Encoder::new(&mut counter), v)?;
    let mut e = Encoder::new(output_buffer(
        counter.length()?,
        usize::try_from(DecodeLimits::PHASE_1.max_local_record_bytes)
            .map_err(|_| FormatError::Overflow)?,
    )?);
    encode_local_state_payload_to(&mut e, v)?;
    Ok(e.into_writer())
}
fn encode_local_state_payload_to<W: minicbor::encode::Write>(
    e: &mut Encoder<W>,
    v: &LocalStatePayload,
) -> Result<(), FormatError> {
    e.array(5)?
        .u16(FORMAT_VERSION_V1)?
        .u8(v.record_type as u8)?
        .bytes(&v.record_id)?
        .u64(u64::try_from(v.payload.len()).map_err(|_| FormatError::Overflow)?)?
        .bytes(&v.payload)?;
    Ok(())
}
pub fn decode_local_state_payload(
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<LocalStatePayload, FormatError> {
    require_depth(limits, 1)?;
    check_input_bound(bytes, u64::from(limits.max_local_record_bytes))?;
    let mut d = Decoder::new(bytes);
    require_array(&mut d, 5)?;
    require_v1(d.u16()?)?;
    let kind = LocalRecordType::try_from(d.u8()?)?;
    let id = fixed_bytes::<32>(d.bytes()?)?;
    let declared = d.u64()?;
    let raw = d.bytes()?;
    if declared != u64::try_from(raw.len()).map_err(|_| FormatError::Overflow)? {
        return Err(FormatError::LengthMismatch);
    }
    let payload = copy_bounded(raw, limits)?;
    finish(&d, bytes)?;
    let v = LocalStatePayload::try_new(kind, id, payload, limits)?;
    let mut writer = CanonicalCompareWriter::new(bytes);
    encode_local_state_payload_to(&mut Encoder::new(&mut writer), &v)?;
    writer.finish()?;
    Ok(v)
}

fn require_v1(v: u16) -> Result<(), FormatError> {
    if v == FORMAT_VERSION_V1 {
        Ok(())
    } else {
        Err(FormatError::UnsupportedVersion(v))
    }
}
