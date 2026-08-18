use notecrypt_store::{PendingRemotePublication, PendingUnprovableRemote};

fn consume_publication(_: PendingRemotePublication) {}

fn consume_acknowledgement(_: PendingUnprovableRemote) {}

fn reuse_publication(value: PendingRemotePublication) {
    consume_publication(value);
    consume_publication(value);
}

fn reuse_acknowledgement(value: PendingUnprovableRemote) {
    consume_acknowledgement(value);
    consume_acknowledgement(value);
}

fn main() {}
