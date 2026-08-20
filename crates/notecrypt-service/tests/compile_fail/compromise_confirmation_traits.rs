use notecrypt_service::CompromiseRekeyConfirmation;
use serde::Serialize;
use std::fmt::{Debug, Display};

fn require_clone<T: Clone>() {}
fn require_debug<T: Debug>() {}
fn require_display<T: Display>() {}
fn require_partial_eq<T: PartialEq>() {}
fn require_eq<T: Eq>() {}
fn require_default<T: Default>() {}
fn require_serialize<T: Serialize>() {}

fn main() {
    require_clone::<CompromiseRekeyConfirmation>();
    require_debug::<CompromiseRekeyConfirmation>();
    require_display::<CompromiseRekeyConfirmation>();
    require_partial_eq::<CompromiseRekeyConfirmation>();
    require_eq::<CompromiseRekeyConfirmation>();
    require_default::<CompromiseRekeyConfirmation>();
    require_serialize::<CompromiseRekeyConfirmation>();
}
