use notecrypt_store::{
    CommittedReachableHead, PendingRemotePublication, PendingUnprovableRemote,
    VerifiedReachableHead,
};

fn requires_equality<T: PartialEq>() {}

fn main() {
    requires_equality::<VerifiedReachableHead>();
    requires_equality::<CommittedReachableHead>();
    requires_equality::<PendingRemotePublication>();
    requires_equality::<PendingUnprovableRemote>();
}
