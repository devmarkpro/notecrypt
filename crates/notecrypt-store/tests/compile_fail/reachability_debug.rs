use notecrypt_store::{
    CommittedReachableHead, PendingRemotePublication, PendingUnprovableRemote,
    VerifiedReachableHead,
};

fn requires_debug<T: std::fmt::Debug>() {}

fn main() {
    requires_debug::<VerifiedReachableHead>();
    requires_debug::<CommittedReachableHead>();
    requires_debug::<PendingRemotePublication>();
    requires_debug::<PendingUnprovableRemote>();
}
