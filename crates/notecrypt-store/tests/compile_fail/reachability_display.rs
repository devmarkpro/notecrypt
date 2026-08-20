use notecrypt_store::{
    CommittedReachableHead, PendingRemotePublication, PendingUnprovableRemote,
    VerifiedReachableHead,
};

fn requires_display<T: std::fmt::Display>() {}

fn main() {
    requires_display::<VerifiedReachableHead>();
    requires_display::<CommittedReachableHead>();
    requires_display::<PendingRemotePublication>();
    requires_display::<PendingUnprovableRemote>();
}
