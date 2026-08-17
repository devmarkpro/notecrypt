use std::fmt;

macro_rules! opaque_id {
    ($name:ident, $size:expr) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $size]);

        impl $name {
            #[must_use]
            pub const fn from_bytes(bytes: [u8; $size]) -> Self {
                Self(bytes)
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $size] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}

opaque_id!(VaultId, 16);
opaque_id!(DeviceId, 16);
opaque_id!(FileId, 16);
opaque_id!(RevisionId, 32);
opaque_id!(SnapshotId, 32);
opaque_id!(ObjectId, 32);

#[cfg(test)]
mod tests {
    use super::{DeviceId, FileId, ObjectId, RevisionId, SnapshotId, VaultId};

    #[test]
    fn identities_compare_and_sort_without_type_confusion() {
        assert!(VaultId::from_bytes([1; 16]) < VaultId::from_bytes([2; 16]));
        assert_eq!(DeviceId::from_bytes([3; 16]), DeviceId::from_bytes([3; 16]));
        assert!(FileId::from_bytes([4; 16]) < FileId::from_bytes([5; 16]));
        assert!(RevisionId::from_bytes([6; 32]) < RevisionId::from_bytes([7; 32]));
        assert!(SnapshotId::from_bytes([8; 32]) < SnapshotId::from_bytes([9; 32]));
    }

    #[test]
    fn object_id_exposes_only_its_fixed_replication_bytes() {
        let bytes = [42; 32];
        let id = ObjectId::from_bytes(bytes);

        assert_eq!(id.as_bytes(), &bytes);
    }
}
