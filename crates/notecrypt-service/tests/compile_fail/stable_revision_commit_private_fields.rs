use notecrypt_service::StableRevisionCommit;

fn inspect(value: StableRevisionCommit<'static>) {
    let _ = value.request;
    let _ = value.source;
    let _ = value.guard;
}

fn main() {}
