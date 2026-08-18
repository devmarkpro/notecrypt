use notecrypt_store::AuthenticatedLogicalEntry;
use serde::Serialize;

fn require_serialize<T: Serialize>() {}

fn main() {
    require_serialize::<AuthenticatedLogicalEntry>();
}
