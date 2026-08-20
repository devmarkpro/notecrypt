use notecrypt_store::{
    CommittedReachableHead, PendingRemotePublication, PendingUnprovableRemote,
    VerifiedReachableHead,
};

fn verified(value: VerifiedReachableHead) {
    let _ = value.binding;
}

fn committed(value: CommittedReachableHead) {
    let _ = value.binding;
}

fn pending_publication(value: PendingRemotePublication) {
    let _ = value.binding;
}

fn pending_unprovable(value: PendingUnprovableRemote) {
    let _ = value.context;
}

fn main() {}
