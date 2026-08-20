use notecrypt_crypto::{HeadAuthenticator, LocalStateAuthenticator};

fn main() {
    let _ = HeadAuthenticator([0; 32]);
    let _ = LocalStateAuthenticator([0; 32]);
}
