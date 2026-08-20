use notecrypt_store::{
    CommittedReachableHead, PendingRemotePublication, PendingUnprovableRemote,
    VerifiedReachableHead,
};

fn requires_default<T: Default>() {}

fn main() {
    requires_default::<VerifiedReachableHead>();
    requires_default::<CommittedReachableHead>();
    requires_default::<PendingRemotePublication>();
    requires_default::<PendingUnprovableRemote>();
}
