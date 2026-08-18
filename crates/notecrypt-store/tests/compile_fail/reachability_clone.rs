use notecrypt_store::{
    CommittedReachableHead, PendingRemotePublication, PendingUnprovableRemote,
    VerifiedReachableHead,
};

fn requires_clone<T: Clone>() {}

fn main() {
    requires_clone::<VerifiedReachableHead>();
    requires_clone::<CommittedReachableHead>();
    requires_clone::<PendingRemotePublication>();
    requires_clone::<PendingUnprovableRemote>();
}
