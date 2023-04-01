use rand::{distributions::Alphanumeric, Rng};
use sha3::{Digest, Keccak256};

// Proxy bytecode - Deplyed contract bytecode doesn't effect the deterministic address.
const KECCAK256_PROXY_CHILD_BYTECODE: [u8; 32] = [
    33, 195, 93, 190, 27, 52, 74, 36, 136, 207, 51, 33, 214, 206, 84, 47, 142, 159, 48, 85, 68,
    255, 9, 228, 153, 58, 98, 49, 154, 73, 124, 31,
];

/// Calculates the address of a contract based on the given deployer and salt.
/// # Arguments
///
/// * `deployer` - A byte slice representing the create3 deployer address.
/// * `prefix` - A string representing the prefix that the resulting address should start with (without 0x).
///
/// # Returns
///
/// A 20-byte array representing the address of the contract.
// @dev note: keccak256(rlp([keccak256(0xff ++ address(this) ++ _salt ++ keccak256(childBytecode))[12:], 0x01]))
pub fn calc_addr(deployer: &[u8], salt: &[u8]) -> [u8; 20] {
    // [contract creation prefix] + [create3 deployer] + [salt] + [keccak256(childBytecode)]
    let salt_hash = Keccak256::digest(salt);
    // println!("Salt hash: 0x{}", hex::encode(&salt_hash));
    let mut bytes: Vec<u8> = Vec::new();
    bytes.push(0xff);
    bytes.extend_from_slice(deployer);
    bytes.extend_from_slice(&salt_hash);
    bytes.extend_from_slice(&KECCAK256_PROXY_CHILD_BYTECODE);
    let hash = Keccak256::digest(&bytes);
    let mut proxy_bytes = [0u8; 20];
    proxy_bytes.copy_from_slice(&hash[12..]);

    // Use proxy address to compute the final contract address.
    // keccak256(rlp(proxy_bytes ++ 0x01)) More here -> https://ethereum.stackexchange.com/a/761/66849
    let mut bytes2: Vec<u8> = Vec::new();
    bytes2.extend_from_slice(&[0xd6, 0x94]); // RLP prefix for a list of two items
    bytes2.extend(&proxy_bytes); // The proxy address
    bytes2.push(0x01); // The nonce of the contract
    let hash2 = Keccak256::digest(&bytes2);

    // resulting hash -> The last 20 bytes (40 characters) of the hash.
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash2[12..]);
    address
}

// todo: write some tests later
// todo: fx naming for prefix and suffix
/// Generates a random salt for a given deployer and prefix.
/// # Arguments
///
/// * `deployer` - A byte slice representing the create3 deployer address.
/// * `prefix` - A string representing the prefix that the resulting address should start with (without 0x).
///
/// # Panics
///
/// This method will panic if the `prefix` is greater than 20 bytes in hexadecimal format.
///
/// # Returns
///
/// A 32-byte array representing the generated salt.
pub fn generate_salt(deployer: &[u8], prefix: &str) -> [u8; 32] {
    let mut salt_bytes = [0; 32];
    let prefix_len = prefix.len();
    if prefix_len > 20 {
        panic!("prefix must be less than or equal to 20 bytes in hexadecimal format");
    }

    loop {
        let salt: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
        let vanity_addr = calc_addr(deployer, &salt.as_bytes());
        let vanity_addr = hex::encode(&vanity_addr);
        if vanity_addr.starts_with(&prefix) {
            let salt_hex = hex::encode(Keccak256::digest(salt.clone()));
            let salt_bytes_slice = hex::decode(&salt_hex).unwrap();
            salt_bytes.copy_from_slice(&salt_bytes_slice);

            println!("\x1b[32mVanity address:\x1b[0m 0x{}", vanity_addr);
            println!("\x1b[32mSalt string:\x1b[0m {}", salt);
            break;
        }
    }
    salt_bytes
}

/// Generates a salt suffix for a given prefix and salt.
///
/// # Arguments
///
/// * `deployer` - A byte slice representing the create3 deployer address.
/// * `salt_suffix` - A string representing the suffix to append to the generated salt.
/// * `prefix` - A string representing the prefix that the resulting address should start with (without 0x).
///
/// # Panics
///
/// This method will panic if the `prefix` is greater than 20 bytes in hexadecimal format.
///
/// # Returns
///
/// A 32-byte array representing the generated salt.
pub fn generate_salt_suffix(deployer: &[u8], salt_suffix: &str, prefix: &str) -> [u8; 32] {
    let mut salt_bytes = [0; 32];
    let prefix_len = prefix.len();
    if prefix_len > 20 {
        panic!("prefix must be less than or equal to 20 bytes in hexadecimal format");
    }

    loop {
        let salt: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(7)
            .map(char::from)
            .collect();
        let salt = salt_suffix.to_owned() + &salt;
        let vanity_addr = calc_addr(deployer, &salt.as_bytes());
        let vanity_addr = hex::encode(&vanity_addr);
        if vanity_addr.starts_with(&prefix) {
            let salt_hex = hex::encode(Keccak256::digest(salt.clone()));
            let salt_bytes_slice = hex::decode(&salt_hex).unwrap();
            salt_bytes.copy_from_slice(&salt_bytes_slice);

            println!("\x1b[32mVanity address:\x1b[0m 0x{}", vanity_addr);
            println!("\x1b[32mSalt string:\x1b[0m {}", salt);
            break;
        }
    }
    salt_bytes
}
