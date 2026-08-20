use notecrypt_store::{
    CommittedReachableHead, PendingRemotePublication, PendingUnprovableRemote,
    VerifiedReachableHead,
};

fn requires_eq<T: Eq>() {}

fn main() {
    requires_eq::<VerifiedReachableHead>();
    requires_eq::<CommittedReachableHead>();
    requires_eq::<PendingRemotePublication>();
    requires_eq::<PendingUnprovableRemote>();
}
