use notecrypt_service::FinalSaveGuard;

fn inaccessible<T>() -> T {
    loop {}
}

fn forge() -> FinalSaveGuard {
    FinalSaveGuard {
        service: inaccessible(),
        state: inaccessible(),
        generation: 1,
        armed: true,
    }
}

fn main() {}
