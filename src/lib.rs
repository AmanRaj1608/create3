use rand::{distributions::Alphanumeric, Rng};
use sha3::{Digest, Keccak256};

// TODO: create fn that accepts salt as &[u8; 32] instead of just &[u8]
// TODO: rename functions in major release to make sense with previously mentioned fn// TODO: should panic/return a Result object if prefix/suffix has incorrect characters
// TODO: add regex fn for salt generation
// TODO: convert panics into Results
// TODO: rename the salt_suffix argument to salt_prefix

// Proxy bytecode - Deplyed contract bytecode doesn't effect the deterministic address.
const KECCAK256_PROXY_CHILD_BYTECODE: [u8; 32] = [
    33, 195, 93, 190, 27, 52, 74, 36, 136, 207, 51, 33, 214, 206, 84, 47, 142, 159, 48, 85, 68,
    255, 9, 228, 153, 58, 98, 49, 154, 73, 124, 31,
];

/// Calculates the address of a contract based on the given deployer and salt.
/// 
/// # Arguments
///
/// * `deployer` - A byte slice representing the create3 deployer address.
/// * `salt` - A string in u8 array format that is digested by keccak256 and used as the salt input.
///
/// # Returns
///
/// A 20-byte array representing the address of the contract.
// @dev note: keccak256(rlp([keccak256(0xff ++ address(this) ++ _salt ++ keccak256(childBytecode))[12:], 0x01]))
pub fn calc_addr(deployer: &[u8], salt: &[u8]) -> [u8; 20] {
    // [contract creation prefix] + [create3 deployer] + [salt] + [keccak256(childBytecode)]
    let salt_hash = Keccak256::digest(salt);
    // println!("Salt hash: 0x{}", hex::encode(&salt_hash));

    calc_addr_with_bytes(deployer, &salt_hash.as_slice()[0.. 32].try_into().unwrap())
}

/// Calculates the address of a contract based on the given deployer and salt.
/// 
/// # Arguments
///
/// * `deployer` - A byte slice representing the create3 deployer address.
/// * `salt` - Bytes in u8 array format that is directly used as the salt input.
///
/// # Returns
///
/// A 20-byte array representing the address of the contract.
pub fn calc_addr_with_bytes(deployer: &[u8], salt: &[u8; 32]) -> [u8; 20] {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.push(0xff);
    bytes.extend_from_slice(deployer);
    bytes.extend_from_slice(salt);
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
/// A tuple where the first element is the string formatted generated salt, and the second element is a 
/// 32-byte array representing the digested generated salt.
pub fn generate_salt_suffix(deployer: &[u8], salt_suffix: &str, prefix: &str) -> (String, [u8; 32]) {
    let mut salt_bytes = [0; 32];
    let mut salt: String;
    let prefix_len = prefix.len();
    if prefix_len > 20 {
        panic!("prefix must be less than or equal to 20 bytes in hexadecimal format");
    }

    loop {
        salt = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(7)
            .map(char::from)
            .collect();
        salt = salt_suffix.to_owned() + &salt;
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
    (salt, salt_bytes)
}

#[cfg(test)]
mod tests {
    use sha3::{Keccak256, Digest};
    use crate::{calc_addr, generate_salt, generate_salt_suffix, calc_addr_with_bytes};

    #[test]
    fn should_calculate_correctly_with_given_salt_string() {
        let deployer: &Vec<u8> = &hex::decode("0fC5025C764cE34df352757e82f7B5c4Df39A836").unwrap();

        // Answers were generated with the Solady CREATE3 library
        // https://github.com/Vectorized/solady/blob/main/src/utils/CREATE3.sol
        let correct_answers: Vec<(&str, &str)> = vec![
            ("a", "BFf47440D3A5E59714F1D995F8b105E2a04AB46A"),
            ("b", "7E10Ca8fa1c8e1528601Fea82F51646182f835b8"),
            ("c", "70b556548FF0161082fB751d5E372eFa0133805C"),
            // https://www.poetryfoundation.org/poems/44263/fire-and-ice
            ("Some say the world will end in fire, Some say in ice. From what I’ve tasted of desire I hold with those who favor fire. But if it had to perish twice, I think I know enough of hate To say that for destruction ice Is also great And would suffice.", "C244c5dEa48e677cE7cAbD05BF8eC220b1a99Fc9")
        ];

        for (salt, answer) in correct_answers.iter() {
            let addr: [u8; 20] = calc_addr(deployer, salt.as_bytes());
            let addr_str = hex::encode(addr);
            assert_eq!(addr_str, answer.to_lowercase());
        }
    }

    #[test]
    fn should_calculate_correctly_with_given_salt() {
        let deployer = &hex::decode("d8b934580fcE35a11B58C6D73aDeE468a2833fa8").unwrap();

        // Answers were generated with the Solady CREATE3 library
        // https://github.com/Vectorized/solady/blob/main/src/utils/CREATE3.sol
        let correct_answers: Vec<(&str, &str)> = vec![
            ("3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb", "442188F25da4ac213D55aE81F1BFB421a4eb4562"),
            ("b5553de315e0edf504d9150af82dafa5c4667fa618ed0a6f19c69b41166c5510", "551b9d8A7106Fdf98e68c4bf12Da1f23ad70C815"),
            ("0b42b6393c1f53060fe3ddbfcd7aadcca894465a5a438f69c87d790b2299b9b2", "43d8e8C69fd771f7D3F4e25697Dadd3cC11D1cDB"),
            ("ead17456afde832907c72ba39033455130a8f4d540a869ba31312c2746bf9c4b", "AB3D55404C5C21D18403A71aF5f6887BD0EC8d56")
        ];

        for (salt, answer) in correct_answers.iter() {
            let salt: [u8; 32] = hex::decode(*salt).unwrap()[0.. 32].try_into().unwrap();
            let addr: [u8; 20] = calc_addr_with_bytes(deployer, &salt);
            let addr_str = hex::encode(addr);
            assert_eq!(addr_str, answer.to_lowercase());
        }
    }

    #[test]
    fn should_generate_with_prefix() {
        let deployer: &Vec<u8> = &hex::decode("5e17b14ADd6c386305A32928F985b29bbA34Eff5").unwrap();
        let runs = vec!["0", "00", "000", "abc", "123", "789"];

        for run in runs.iter() {
            let salt = generate_salt(deployer, run);
            
            /* NOTE: 
             * This essentially repeats the code in generate_salt. Could be useful for future changes of the function. 
             * Is there a better way of testing this?
            */ 
            let addr: [u8; 20] = calc_addr_with_bytes(deployer, &salt);

            assert!(hex::encode(addr).starts_with(run));
        }
    }

    #[test]
    fn should_generate_with_empty_prefix() {
        let deployer: &Vec<u8> = &hex::decode("0fC5025C764cE34df352757e82f7B5c4Df39A836").unwrap();
        generate_salt(deployer, "");
    }

    #[test]
    fn should_generate_with_salt_prefix() {
        let deployer: &Vec<u8> = &hex::decode("5e17b14ADd6c386305A32928F985b29bbA34Eff5").unwrap();
        let runs = vec!["0", "00", "000", "abc", "123", "789"];
        let salt_prefix = "testpfx_";
        for run in runs.iter() {
            let (salt, digested_salt) = generate_salt_suffix(deployer, salt_prefix, run);
            assert!(salt.starts_with(salt_prefix));
            assert_eq!(Keccak256::digest(salt).as_slice()[0.. 32], digested_salt);
            assert!(hex::encode(calc_addr_with_bytes(deployer, &digested_salt)).starts_with(run));
        }
    }

    #[test]
    #[should_panic]
    fn generate_salt_should_panic_if_prefix_is_greater_than_20_bytes() {
        let deployer = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045".as_bytes();
        let prefix = "0x00000000000000000000000000000000000000000";
        generate_salt(deployer, prefix);
    }

    #[test]
    #[should_panic]
    fn generate_salt_suffix_should_panic_if_prefix_is_greater_than_20_bytes() {
        let deployer = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045".as_bytes();
        let suffix = "";
        let prefix = "0x00000000000000000000000000000000000000000";
        generate_salt_suffix(deployer, suffix, prefix);
    }
}
