use notecrypt_store::VaultRepair;

fn require_clone<T: Clone>() {}
fn require_debug<T: std::fmt::Debug>() {}
fn require_default<T: Default>() {}
fn require_display<T: std::fmt::Display>() {}
fn require_equality<T: Eq + PartialEq>() {}
fn require_serialize<T: serde::Serialize>() {}

fn main() {
    require_clone::<VaultRepair>();
    require_debug::<VaultRepair>();
    require_default::<VaultRepair>();
    require_display::<VaultRepair>();
    require_equality::<VaultRepair>();
    require_serialize::<VaultRepair>();
}
