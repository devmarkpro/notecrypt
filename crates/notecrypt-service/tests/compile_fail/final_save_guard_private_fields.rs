use notecrypt_service::FinalSaveGuard;

fn inspect(value: FinalSaveGuard) {
    let _ = value.service;
    let _ = value.state;
    let _ = value.generation;
    let _ = value.armed;
}

fn main() {}
