use std::sync::Arc;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PersistentTrie<const N: usize, V> {
    root: Option<NodePtr<N, V>>,
    len: usize,
}

impl<const N: usize, V> Default for PersistentTrie<N, V> {
    fn default() -> Self {
        Self { root: None, len: 0 }
    }
}

#[derive(Clone, PartialEq, Eq)]
enum NodePtr<const N: usize, V> {
    Branch(Arc<Branch<N, V>>),
    Leaf(Arc<Leaf<N, V>>),
}

#[derive(PartialEq, Eq)]
struct Branch<const N: usize, V> {
    bit: usize,
    zero: NodePtr<N, V>,
    one: NodePtr<N, V>,
}

#[derive(PartialEq, Eq)]
struct Leaf<const N: usize, V> {
    key: [u8; N],
    value: V,
}

impl<const N: usize, V: Clone> PersistentTrie<N, V> {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn insert(&mut self, key: [u8; N], value: V) {
        let Some(root) = self.root.as_ref() else {
            self.root = Some(new_leaf(key, value));
            self.len = 1;
            return;
        };
        let existing = lookup_leaf(root, &key);
        if existing.key == key {
            self.root = Some(replace_value(root, &key, value));
            return;
        }

        let differing_bit = first_differing_bit(&existing.key, &key)
            .expect("distinct fixed-width keys differ at some bit");
        self.root = Some(insert_distinct(root, key, value, differing_bit));
        self.len += 1;
    }

    pub(crate) fn remove(&mut self, key: &[u8; N]) -> Option<V> {
        let removed = self.get(key)?.clone();
        self.root = remove_existing(
            self.root.as_ref().expect("a found key implies a root node"),
            key,
        );
        self.len -= 1;
        Some(removed)
    }

    pub(crate) fn get(&self, key: &[u8; N]) -> Option<&V> {
        let leaf = lookup_leaf(self.root.as_ref()?, key);
        (leaf.key == *key).then_some(&leaf.value)
    }

    pub(crate) fn contains_key(&self, key: &[u8; N]) -> bool {
        self.get(key).is_some()
    }

    pub(crate) fn values(&self) -> Vec<&V> {
        let mut values = Vec::with_capacity(self.len);
        if let Some(root) = self.root.as_ref() {
            collect_values(root, &mut values);
        }
        values
    }

    pub(crate) fn key_values(&self) -> Vec<(&[u8; N], &V)> {
        let mut entries = Vec::with_capacity(self.len);
        if let Some(root) = self.root.as_ref() {
            collect_key_values(root, &mut entries);
        }
        entries
    }

    pub(crate) fn values_with_byte_prefix(&self, prefix: &[u8]) -> Vec<&V> {
        assert!(prefix.len() <= N, "prefix cannot exceed the trie key");
        let Some(mut node) = self.root.as_ref() else {
            return Vec::new();
        };
        let prefix_bits = prefix.len() * 8;
        loop {
            visit_node();
            match node {
                NodePtr::Branch(branch) if branch.bit < prefix_bits => {
                    node = if prefix_bit(prefix, branch.bit) {
                        &branch.one
                    } else {
                        &branch.zero
                    };
                }
                NodePtr::Branch(_) | NodePtr::Leaf(_) => break,
            }
        }
        if !first_leaf(node).key.starts_with(prefix) {
            return Vec::new();
        }
        let mut values = Vec::new();
        collect_values(node, &mut values);
        values
    }

    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    #[cfg(test)]
    pub(crate) fn retained_node_count(&self) -> usize {
        self.root.as_ref().map_or(0, count_nodes)
    }

    #[cfg(test)]
    pub(crate) fn estimated_retained_node_bytes(&self) -> usize {
        if self.len == 0 {
            return 0;
        }
        let arc_header = 2 * size_of::<usize>();
        self.len * (size_of::<Leaf<N, V>>() + arc_header)
            + (self.len - 1) * (size_of::<Branch<N, V>>() + arc_header)
    }
}

fn new_leaf<const N: usize, V>(key: [u8; N], value: V) -> NodePtr<N, V> {
    allocate_node();
    NodePtr::Leaf(Arc::new(Leaf { key, value }))
}

fn new_branch<const N: usize, V>(
    bit: usize,
    zero: NodePtr<N, V>,
    one: NodePtr<N, V>,
) -> NodePtr<N, V> {
    allocate_node();
    NodePtr::Branch(Arc::new(Branch { bit, zero, one }))
}

fn lookup_leaf<'a, const N: usize, V>(
    mut node: &'a NodePtr<N, V>,
    key: &[u8; N],
) -> &'a Leaf<N, V> {
    loop {
        visit_node();
        match node {
            NodePtr::Branch(branch) => {
                node = if key_bit(key, branch.bit) {
                    &branch.one
                } else {
                    &branch.zero
                };
            }
            NodePtr::Leaf(leaf) => return leaf,
        }
    }
}

fn first_leaf<const N: usize, V>(mut node: &NodePtr<N, V>) -> &Leaf<N, V> {
    loop {
        visit_node();
        match node {
            NodePtr::Branch(branch) => node = &branch.zero,
            NodePtr::Leaf(leaf) => return leaf,
        }
    }
}

fn replace_value<const N: usize, V: Clone>(
    node: &NodePtr<N, V>,
    key: &[u8; N],
    value: V,
) -> NodePtr<N, V> {
    visit_node();
    match node {
        NodePtr::Leaf(_) => new_leaf(*key, value),
        NodePtr::Branch(branch) if key_bit(key, branch.bit) => new_branch(
            branch.bit,
            branch.zero.clone(),
            replace_value(&branch.one, key, value),
        ),
        NodePtr::Branch(branch) => new_branch(
            branch.bit,
            replace_value(&branch.zero, key, value),
            branch.one.clone(),
        ),
    }
}

fn insert_distinct<const N: usize, V: Clone>(
    node: &NodePtr<N, V>,
    key: [u8; N],
    value: V,
    differing_bit: usize,
) -> NodePtr<N, V> {
    visit_node();
    if let NodePtr::Branch(branch) = node
        && branch.bit < differing_bit
    {
        return if key_bit(&key, branch.bit) {
            new_branch(
                branch.bit,
                branch.zero.clone(),
                insert_distinct(&branch.one, key, value, differing_bit),
            )
        } else {
            new_branch(
                branch.bit,
                insert_distinct(&branch.zero, key, value, differing_bit),
                branch.one.clone(),
            )
        };
    }

    let leaf = new_leaf(key, value);
    if key_bit(&key, differing_bit) {
        new_branch(differing_bit, node.clone(), leaf)
    } else {
        new_branch(differing_bit, leaf, node.clone())
    }
}

fn remove_existing<const N: usize, V: Clone>(
    node: &NodePtr<N, V>,
    key: &[u8; N],
) -> Option<NodePtr<N, V>> {
    visit_node();
    match node {
        NodePtr::Leaf(_) => None,
        NodePtr::Branch(branch) if key_bit(key, branch.bit) => remove_existing(&branch.one, key)
            .map_or_else(
                || Some(branch.zero.clone()),
                |one| Some(new_branch(branch.bit, branch.zero.clone(), one)),
            ),
        NodePtr::Branch(branch) => remove_existing(&branch.zero, key).map_or_else(
            || Some(branch.one.clone()),
            |zero| Some(new_branch(branch.bit, zero, branch.one.clone())),
        ),
    }
}

fn first_differing_bit<const N: usize>(left: &[u8; N], right: &[u8; N]) -> Option<usize> {
    left.iter()
        .zip(right)
        .enumerate()
        .find_map(|(byte_index, (left, right))| {
            let difference = left ^ right;
            (difference != 0).then(|| byte_index * 8 + difference.leading_zeros() as usize)
        })
}

fn key_bit<const N: usize>(key: &[u8; N], bit: usize) -> bool {
    key[bit / 8] & (1 << (7 - bit % 8)) != 0
}

fn prefix_bit(prefix: &[u8], bit: usize) -> bool {
    prefix[bit / 8] & (1 << (7 - bit % 8)) != 0
}

fn collect_values<'a, const N: usize, V>(node: &'a NodePtr<N, V>, values: &mut Vec<&'a V>) {
    visit_node();
    match node {
        NodePtr::Branch(branch) => {
            collect_values(&branch.zero, values);
            collect_values(&branch.one, values);
        }
        NodePtr::Leaf(leaf) => values.push(&leaf.value),
    }
}

fn collect_key_values<'a, const N: usize, V>(
    node: &'a NodePtr<N, V>,
    entries: &mut Vec<(&'a [u8; N], &'a V)>,
) {
    visit_node();
    match node {
        NodePtr::Branch(branch) => {
            collect_key_values(&branch.zero, entries);
            collect_key_values(&branch.one, entries);
        }
        NodePtr::Leaf(leaf) => entries.push((&leaf.key, &leaf.value)),
    }
}

#[cfg(test)]
fn count_nodes<const N: usize, V>(node: &NodePtr<N, V>) -> usize {
    match node {
        NodePtr::Branch(branch) => 1 + count_nodes(&branch.zero) + count_nodes(&branch.one),
        NodePtr::Leaf(_) => 1,
    }
}

#[cfg(test)]
thread_local! {
    static NODE_VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static NODE_ALLOCATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[inline]
fn visit_node() {
    #[cfg(test)]
    NODE_VISITS.with(|visits| visits.set(visits.get() + 1));
}

#[inline]
fn allocate_node() {
    #[cfg(test)]
    NODE_ALLOCATIONS.with(|allocations| allocations.set(allocations.get() + 1));
}

#[cfg(test)]
pub(crate) fn measure_node_visits<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    NODE_VISITS.with(|visits| visits.set(0));
    let result = operation();
    let visits = NODE_VISITS.with(std::cell::Cell::get);
    (result, visits)
}

#[cfg(test)]
fn measure_node_allocations<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    NODE_ALLOCATIONS.with(|allocations| allocations.set(0));
    let result = operation();
    let allocations = NODE_ALLOCATIONS.with(std::cell::Cell::get);
    (result, allocations)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        mem::size_of,
        sync::Arc,
    };

    use super::{Branch, NodePtr, PersistentTrie, measure_node_allocations};

    #[test]
    fn insert_replace_remove_and_prefix_lookup_are_persistent() {
        let mut first = PersistentTrie::<2, u8>::new();
        first.insert([1, 1], 10);
        first.insert([1, 2], 20);
        first.insert([2, 1], 30);
        let original = first.clone();

        first.insert([1, 1], 11);
        first.remove(&[1, 2]);

        assert_eq!(original.get(&[1, 1]), Some(&10));
        assert_eq!(original.get(&[1, 2]), Some(&20));
        assert_eq!(first.get(&[1, 1]), Some(&11));
        assert_eq!(first.get(&[1, 2]), None);
        assert_eq!(first.values_with_byte_prefix(&[1]), vec![&11]);
    }

    #[test]
    fn retained_nodes_are_bounded_by_a_compact_binary_tree() {
        let mut trie = PersistentTrie::<8, u64>::new();
        for value in 0_u64..10_000 {
            trie.insert(value.to_be_bytes(), value);
        }

        assert_eq!(trie.retained_node_count(), 19_999);
        assert_eq!(trie.get(&9_999_u64.to_be_bytes()), Some(&9_999));
    }

    #[test]
    fn update_allocations_follow_actual_branch_depth() {
        let mut trie = PersistentTrie::<8, u64>::new();
        for value in 0_u64..10_000 {
            trie.insert(value.to_be_bytes(), value);
        }

        let (_, allocations) = measure_node_allocations(|| {
            trie.insert(9_999_u64.to_be_bytes(), 10_000);
        });

        assert!(allocations <= 8 * 8 + 2);
        assert_eq!(trie.get(&9_999_u64.to_be_bytes()), Some(&10_000));
    }

    #[test]
    fn insert_and_remove_allocations_follow_actual_branch_depth() {
        let mut trie = PersistentTrie::<8, u64>::new();
        for value in 0_u64..10_000 {
            trie.insert(value.to_be_bytes(), value);
        }

        let (_, insert_allocations) = measure_node_allocations(|| {
            trie.insert(20_000_u64.to_be_bytes(), 20_000);
        });
        let (_, remove_allocations) = measure_node_allocations(|| {
            assert_eq!(trie.remove(&20_000_u64.to_be_bytes()), Some(20_000));
        });

        assert!(insert_allocations <= 8 * 8 + 2);
        assert!(remove_allocations <= 8 * 8 + 2);
    }

    #[test]
    fn branch_and_pointer_layout_do_not_grow_with_the_value() {
        assert_eq!(
            size_of::<NodePtr<8, [u8; 4_096]>>(),
            size_of::<NodePtr<8, u8>>()
        );
        assert_eq!(
            size_of::<Branch<8, [u8; 4_096]>>(),
            size_of::<Branch<8, u8>>()
        );
    }

    #[test]
    fn ordering_prefixes_and_mutations_match_a_btree_model() {
        let mut trie = PersistentTrie::<2, u16>::new();
        let mut model = BTreeMap::new();
        let mut state = 0x1234_5678_u64;
        for step in 0_u16..2_000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let key = (state >> 24) as u16;
            if state & 3 == 0 {
                assert_eq!(trie.remove(&key.to_be_bytes()), model.remove(&key));
            } else {
                trie.insert(key.to_be_bytes(), step);
                model.insert(key, step);
            }
            assert_eq!(
                trie.values().into_iter().copied().collect::<Vec<_>>(),
                model.values().copied().collect::<Vec<_>>()
            );
        }

        for prefix in 0_u16..=255 {
            let expected = model
                .range((prefix << 8)..=((prefix << 8) | 0xff))
                .map(|(_, value)| *value)
                .collect::<Vec<_>>();
            assert_eq!(
                trie.values_with_byte_prefix(&[prefix as u8])
                    .into_iter()
                    .copied()
                    .collect::<Vec<_>>(),
                expected
            );
        }
        assert_eq!(
            trie.values_with_byte_prefix(&[])
                .into_iter()
                .copied()
                .collect::<Vec<_>>(),
            model.values().copied().collect::<Vec<_>>()
        );
        for key in model.keys().take(32) {
            let bytes = key.to_be_bytes();
            for prefix_len in 0..=bytes.len() {
                let expected = model
                    .iter()
                    .filter(|(candidate, _)| {
                        candidate.to_be_bytes().starts_with(&bytes[..prefix_len])
                    })
                    .map(|(_, value)| *value)
                    .collect::<Vec<_>>();
                assert_eq!(
                    trie.values_with_byte_prefix(&bytes[..prefix_len])
                        .into_iter()
                        .copied()
                        .collect::<Vec<_>>(),
                    expected
                );
            }
        }
    }

    #[test]
    fn insertion_permutations_have_canonical_shape_and_common_prefixes() {
        let keys = [[0xaa, 0, 1], [0xaa, 0, 2], [0xaa, 0xff, 3], [0xab, 0, 4]];
        let mut forward = PersistentTrie::<3, [u8; 3]>::new();
        let mut reverse = PersistentTrie::<3, [u8; 3]>::new();
        for key in keys {
            forward.insert(key, key);
        }
        for key in keys.into_iter().rev() {
            reverse.insert(key, key);
        }

        assert!(forward == reverse);
        assert_structure(&forward);
        assert_eq!(forward.values_with_byte_prefix(&[0xaa]).len(), 3);
        assert!(forward.values_with_byte_prefix(&[0xaa, 1]).is_empty());
        assert!(forward.remove(&[0, 0, 0]).is_none());
        for key in keys {
            assert_eq!(forward.remove(&key), Some(key));
        }
        assert_eq!(forward.retained_node_count(), 0);
    }

    #[test]
    fn retained_byte_estimate_tracks_leaf_and_branch_allocations() {
        let mut trie = PersistentTrie::<8, u64>::new();
        trie.insert(1_u64.to_be_bytes(), 1);
        let one = trie.estimated_retained_node_bytes();
        trie.insert(2_u64.to_be_bytes(), 2);

        assert!(one > 0);
        assert!(trie.estimated_retained_node_bytes() > one);
    }

    #[test]
    fn retained_snapshots_share_unaffected_nodes_and_keep_old_values() {
        let mut current = PersistentTrie::<8, u64>::new();
        for value in 0_u64..1_000 {
            current.insert(value.to_be_bytes(), value);
        }
        let base_nodes = current.retained_node_count();
        let original = current.clone();
        let mut snapshots = vec![original.clone()];
        let (_, allocations) = measure_node_allocations(|| {
            for revision in 1_u64..=1_000 {
                current.insert(500_u64.to_be_bytes(), 10_000 + revision);
                snapshots.push(current.clone());
            }
        });

        assert!(allocations <= 1_000 * (8 * 8 + 2));
        assert_eq!(original.get(&500_u64.to_be_bytes()), Some(&500));
        assert_eq!(snapshots[500].get(&500_u64.to_be_bytes()), Some(&10_500));
        assert_eq!(current.get(&500_u64.to_be_bytes()), Some(&11_000));
        let unique_nodes = unique_node_count(&snapshots.iter().collect::<Vec<_>>());
        assert!(unique_nodes <= base_nodes + allocations);
    }

    #[test]
    fn updating_one_side_preserves_the_other_branch_allocation() {
        let mut trie = PersistentTrie::<1, u8>::new();
        trie.insert([0], 1);
        trie.insert([0x80], 2);
        let before = trie.clone();
        trie.insert([0], 3);

        let (NodePtr::Branch(before_root), NodePtr::Branch(after_root)) =
            (before.root.as_ref().unwrap(), trie.root.as_ref().unwrap())
        else {
            panic!("two keys that differ in the first bit create a branch");
        };
        assert!(node_ptr_eq(&before_root.one, &after_root.one));
        assert_eq!(before.get(&[0x80]), Some(&2));
        assert_eq!(trie.get(&[0x80]), Some(&2));
    }

    fn node_ptr_eq<const N: usize, V>(left: &NodePtr<N, V>, right: &NodePtr<N, V>) -> bool {
        match (left, right) {
            (NodePtr::Branch(left), NodePtr::Branch(right)) => Arc::ptr_eq(left, right),
            (NodePtr::Leaf(left), NodePtr::Leaf(right)) => Arc::ptr_eq(left, right),
            (NodePtr::Branch(_), NodePtr::Leaf(_)) | (NodePtr::Leaf(_), NodePtr::Branch(_)) => {
                false
            }
        }
    }

    fn unique_node_count<const N: usize, V>(tries: &[&PersistentTrie<N, V>]) -> usize {
        fn visit<const N: usize, V>(node: &NodePtr<N, V>, seen: &mut BTreeSet<(bool, usize)>) {
            match node {
                NodePtr::Branch(branch) => {
                    if seen.insert((true, Arc::as_ptr(branch) as usize)) {
                        visit(&branch.zero, seen);
                        visit(&branch.one, seen);
                    }
                }
                NodePtr::Leaf(leaf) => {
                    seen.insert((false, Arc::as_ptr(leaf) as usize));
                }
            }
        }

        let mut seen = BTreeSet::new();
        for trie in tries {
            if let Some(root) = trie.root.as_ref() {
                visit(root, &mut seen);
            }
        }
        seen.len()
    }

    fn assert_structure<const N: usize, V>(trie: &PersistentTrie<N, V>) {
        fn visit<const N: usize, V>(node: &NodePtr<N, V>, previous_bit: Option<usize>) {
            if let NodePtr::Branch(branch) = node {
                assert!(branch.bit < N * 8);
                assert!(previous_bit.is_none_or(|previous| branch.bit > previous));
                assert!(!super::key_bit(
                    &super::first_leaf(&branch.zero).key,
                    branch.bit
                ));
                assert!(super::key_bit(
                    &super::first_leaf(&branch.one).key,
                    branch.bit
                ));
                visit(&branch.zero, Some(branch.bit));
                visit(&branch.one, Some(branch.bit));
            }
        }

        if let Some(root) = trie.root.as_ref() {
            visit(root, None);
        }
    }
}
