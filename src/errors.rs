use std::{error::Error, fmt::Display};

/// Errors for generating a CREATE3 salt.
#[derive(Debug, PartialEq)]
pub enum Create3GenerateSaltError {
    /// Occurs if the prefix is too long. The prefix must be less than or equal to 20 bytes.
    PrefixTooLong,
    // Occurs if the prefix is not a hex encoded string. The prefix must be in hexadecimal format.
    PrefixNotHexEncoded,
}

impl Error for Create3GenerateSaltError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl Display for Create3GenerateSaltError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Create3GenerateSaltError::PrefixTooLong => 
                "Create3GenerateSaltError::PrefixTooLong: the prefix is too long. The prefix must be less than or equal to 20 bytes.",
            Create3GenerateSaltError::PrefixNotHexEncoded => 
                "Create3GenerateSaltError::PrefixNotHexEncoded: the prefix is not a hex encoded string. The prefix must be in hexadecimal format.",
        })
    }
}