use std::fmt::{Debug, Display};

use notecrypt_crypto::PublicAeadEnvelopeParts;
use serde::Serialize;

fn assert_clone<T: Clone>() {}
fn assert_debug<T: Debug>() {}
fn assert_display<T: Display>() {}
fn assert_serialize<T: Serialize>() {}

fn main() {
    assert_clone::<PublicAeadEnvelopeParts>();
    assert_debug::<PublicAeadEnvelopeParts>();
    assert_display::<PublicAeadEnvelopeParts>();
    assert_serialize::<PublicAeadEnvelopeParts>();
}
