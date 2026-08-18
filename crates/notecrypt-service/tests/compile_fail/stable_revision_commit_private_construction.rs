use notecrypt_service::StableRevisionCommit;

fn inaccessible<T>() -> T {
    loop {}
}

fn forge() -> StableRevisionCommit<'static> {
    StableRevisionCommit::new(inaccessible(), inaccessible(), inaccessible())
}

fn main() {
    let _ = forge();
}
