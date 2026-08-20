use crate::{CoreError, Entry, EntryKind, FileId, persistent::PersistentTrie};

#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct TreeIndexes {
    children: PersistentTrie<32, FileId>,
    destinations: PersistentTrie<48, DestinationBucket>,
}

#[derive(Clone, Default, PartialEq, Eq)]
struct DestinationBucket(Vec<(String, FileId)>);

impl TreeIndexes {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn from_entries<'a>(
        entries: impl IntoIterator<Item = &'a Entry>,
    ) -> Result<Self, CoreError> {
        let mut indexes = Self::new();
        for entry in entries {
            indexes.add(entry)?;
        }
        Ok(indexes)
    }

    pub(crate) fn add(&mut self, entry: &Entry) -> Result<(), CoreError> {
        if !entry.is_live() || entry.kind() == EntryKind::Root {
            return Ok(());
        }
        let parent = entry.parent().expect("live non-root entries have parents");
        let name = entry.name().expect("live non-root entries have names");
        let collision_key = name.collision_key();
        if self.destination(parent, &collision_key).is_some() {
            return Err(CoreError::DuplicateDestination);
        }

        self.children
            .insert(child_key(parent, entry.id()), entry.id());
        let key = destination_key(parent, &collision_key);
        let mut bucket = self.destinations.get(&key).cloned().unwrap_or_default();
        bucket.0.push((collision_key, entry.id()));
        bucket.0.sort();
        self.destinations.insert(key, bucket);
        Ok(())
    }

    pub(crate) fn remove(&mut self, entry: &Entry) {
        if !entry.is_live() || entry.kind() == EntryKind::Root {
            return;
        }
        let parent = entry.parent().expect("live non-root entries have parents");
        let collision_key = entry
            .name()
            .expect("live non-root entries have names")
            .collision_key();
        self.children.remove(&child_key(parent, entry.id()));

        let key = destination_key(parent, &collision_key);
        let mut bucket = self
            .destinations
            .get(&key)
            .cloned()
            .expect("indexed entries have destination buckets");
        bucket
            .0
            .retain(|(existing, id)| existing != &collision_key || *id != entry.id());
        if bucket.0.is_empty() {
            self.destinations.remove(&key);
        } else {
            self.destinations.insert(key, bucket);
        }
    }

    pub(crate) fn destination(&self, parent: FileId, collision_key: &str) -> Option<FileId> {
        self.destinations
            .get(&destination_key(parent, collision_key))?
            .0
            .iter()
            .find_map(|(existing, id)| (existing == collision_key).then_some(*id))
    }

    pub(crate) fn children(&self, parent: FileId) -> Vec<FileId> {
        self.children
            .values_with_byte_prefix(parent.as_bytes())
            .into_iter()
            .copied()
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn retained_node_count(&self) -> usize {
        self.children.retained_node_count() + self.destinations.retained_node_count()
    }

    #[cfg(test)]
    pub(crate) fn estimated_retained_node_bytes(&self) -> usize {
        self.children.estimated_retained_node_bytes()
            + self.destinations.estimated_retained_node_bytes()
    }
}

fn child_key(parent: FileId, child: FileId) -> [u8; 32] {
    let mut key = [0_u8; 32];
    key[..16].copy_from_slice(parent.as_bytes());
    key[16..].copy_from_slice(child.as_bytes());
    key
}

fn destination_key(parent: FileId, collision_key: &str) -> [u8; 48] {
    let mut key = [0_u8; 48];
    key[..16].copy_from_slice(parent.as_bytes());
    key[16..].copy_from_slice(blake3::hash(collision_key.as_bytes()).as_bytes());
    key
}

#[cfg(test)]
mod tests {
    use super::TreeIndexes;
    use crate::{Entry, EntryName, FileEntry, FileId, RevisionId};

    #[test]
    fn destination_buckets_match_full_normalized_keys() {
        let parent = FileId::from_bytes([1; 16]);
        let entry = Entry::File {
            parent,
            file: FileEntry::new(
                FileId::from_bytes([2; 16]),
                EntryName::parse("note").unwrap(),
                RevisionId::from_bytes([3; 32]),
            ),
        };
        let indexes = TreeIndexes::from_entries([&entry]).unwrap();

        assert_eq!(
            indexes.destination(parent, &EntryName::parse("NOTE").unwrap().collision_key()),
            Some(entry.id()),
        );
    }
}
