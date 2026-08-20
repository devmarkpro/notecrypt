use notecrypt_store::{
    CommittedReachableHead, PendingRemotePublication, PendingUnprovableRemote,
    VerifiedReachableHead,
};

fn requires_serialize<T: serde::Serialize>() {}

fn main() {
    requires_serialize::<VerifiedReachableHead>();
    requires_serialize::<CommittedReachableHead>();
    requires_serialize::<PendingRemotePublication>();
    requires_serialize::<PendingUnprovableRemote>();
}
