use notecrypt_crypto::DeviceWrappingKey;
use notecrypt_service::DeviceUnlockSecret;

fn forge(key: DeviceWrappingKey) -> DeviceUnlockSecret {
    DeviceUnlockSecret(key)
}

fn main() {}
