use create3::{calc_addr, errors::Create3GenerateSaltError, generate_salt, generate_salt_prefix, calc_addr_with_bytes};
use std::io::{self, Write};

fn main() {
    println!("\x1b[32m=========================\x1b[0m");
    println!("\x1b[32m=  CREATE3 ADDRESS TOOL  =\x1b[0m");
    println!("\x1b[32m=========================\x1b[0m");

    loop {
        println!("\n\x1b[36mWhat would you like to do?\x1b[0m");
        println!("\x1b[33m1. Generate CREATE3 address\x1b[0m");
        println!("\x1b[33m2. Generate salt for prefixed address\x1b[0m");
        println!("\x1b[33m3. Generate optimised suffix for prefixed address and salt\x1b[0m");
        print!("\x1b[36mEnter your choice (1/2/3):\x1b[0m ");
        io::stdout().flush().unwrap();

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).unwrap();
        let choice = choice.trim();

        match choice {
            "1" => {
                print!("\x1b[36mEnter deployer address (with '0x' prefix):\x1b[0m ");
                io::stdout().flush().unwrap();
                let mut deployer = String::new();
                io::stdin().read_line(&mut deployer).unwrap();
                let deployer = deployer.trim().trim_start_matches("0x");

                print!("\x1b[36mEnter salt (utf8):\x1b[0m ");
                io::stdout().flush().unwrap();
                let mut salt = String::new();
                io::stdin().read_line(&mut salt).unwrap();
                let salt = salt.trim();

                let address = calc_addr(&hex::decode(deployer).unwrap(), salt.as_bytes());
                println!(
                    "\x1b[32mCREATE3 address:\x1b[0m 0x{}",
                    hex::encode(&address)
                );
                break;
            }
            "2" => {
                print!("\x1b[36mEnter deployer address (with '0x' prefix):\x1b[0m ");
                io::stdout().flush().unwrap();
                let mut deployer = String::new();
                io::stdin().read_line(&mut deployer).unwrap();
                let deployer = deployer.trim().trim_start_matches("0x");
                let deployer = &hex::decode(deployer).unwrap();

                let salt;
                let mut prefix;

                print!("\x1b[36mEnter prefix (without '0x' prefix):\x1b[0m ");
                loop {
                    io::stdout().flush().unwrap();
                    prefix = String::new();
                    io::stdin().read_line(&mut prefix).unwrap();
                    prefix = prefix.trim().to_owned();

                    match generate_salt(deployer, &prefix) {
                        Ok(s) => {
                            salt = s;
                            break;
                        }
                        Err(Create3GenerateSaltError::PrefixNotHexEncoded) => {
                            print!("\x1b[36mInput was not hex encoded. Please enter prefix (without '0x' prefix):\x1b[0m ")
                        }
                        Err(Create3GenerateSaltError::PrefixTooLong) => {
                            print!("\x1b[36mPrefix was too long (over 20 characters). Please enter prefix (without '0x' prefix):\x1b[0m ")
                        }
                    }
                }

                println!("\x1b[32mVanity address:\x1b[0m 0x{}", hex::encode(calc_addr_with_bytes(deployer, &salt.1)));
                println!("\x1b[32mSalt string:\x1b[0m {}", salt.0);
                println!("\x1b[32mHashed salt for prefix {}:\x1b[0m 0x{}", prefix, hex::encode(salt.1));
                break;
            }
            "3" => {
                print!("\x1b[36mEnter deployer address (with '0x' prefix):\x1b[0m ");
                io::stdout().flush().unwrap();
                let mut deployer = String::new();
                io::stdin().read_line(&mut deployer).unwrap();
                let deployer = deployer.trim().trim_start_matches("0x");

                print!("\x1b[36mEnter salt prefix (utf8):\x1b[0m ");
                io::stdout().flush().unwrap();
                let mut salt_prefix = String::new();
                io::stdin().read_line(&mut salt_prefix).unwrap();
                let salt_prefix = salt_prefix.trim();

                let mut prefix;
                let generated;
                let vanity_addr;
                let deployer = &hex::decode(deployer).unwrap();

                print!("\x1b[36mEnter address prefix (without '0x' prefix):\x1b[0m ");
                loop {
                    io::stdout().flush().unwrap();
                    prefix = String::new();
                    io::stdin().read_line(&mut prefix).unwrap();
                    prefix = prefix.trim().to_owned();

                    match generate_salt_prefix(deployer, salt_prefix, &prefix) {
                        Ok(s) => {
                            generated = s;
                            vanity_addr = calc_addr_with_bytes(deployer, &generated.1);
                            break;
                        }
                        Err(Create3GenerateSaltError::PrefixNotHexEncoded) => {
                            print!("\x1b[36mInput was not hex encoded. Please enter prefix (without '0x' prefix):\x1b[0m ")
                        }
                        Err(Create3GenerateSaltError::PrefixTooLong) => {
                            print!("\x1b[36mPrefix was too long (over 20 characters). Please enter prefix (without '0x' prefix):\x1b[0m ")
                        }
                    }
                }

                println!("\x1b[32mVanity address:\x1b[0m 0x{}", hex::encode(vanity_addr));
                println!("\x1b[32mSalt string for prefix {}:\x1b[0m {}", salt_prefix, generated.0);
                println!("\x1b[32mHashed salt :\x1b[0m 0x{}", hex::encode(&generated.1));
                break;
            }
            _ => {
                println!("\x1b[31Invalid choice, please try again.\x1b[0m");
            }
        }
    }
}
