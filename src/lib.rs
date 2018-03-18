//! *lamport* implements one-time hash-based signatures using the Lamport signature scheme.
#![feature(test)]
#![deny(missing_docs, missing_debug_implementations, missing_copy_implementations, trivial_casts,
        trivial_numeric_casts, unsafe_code, unused_import_braces, unused_qualifications)]

extern crate rand;
extern crate ring;
extern crate subtle;
extern crate test;

use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use rand::{OsRng, Rng};
use ring::digest::{digest, Algorithm};
use subtle::{byte_is_nonzero, slices_equal};

/// A type alias defining a Lamport signature
pub type LamportSignatureData = Vec<Vec<u8>>;

/// A one-time signing public key
#[derive(Clone, Debug)]
pub struct PublicKey {
    zero_values: Vec<Vec<u8>>,
    one_values: Vec<Vec<u8>>,
    algorithm: &'static Algorithm,
}

impl PartialEq for PublicKey {
    #[allow(trivial_casts)]
    fn eq(&self, other: &Self) -> bool {
        self.algorithm as *const Algorithm == other.algorithm as *const Algorithm
            && self.zero_values == other.zero_values && self.one_values == other.one_values
    }
}

impl Eq for PublicKey {}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &PublicKey) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKey {
    #[allow(trivial_casts)]
    fn cmp(&self, other: &PublicKey) -> Ordering {
        self.zero_values
            .cmp(&other.zero_values)
            .then(self.one_values.cmp(&other.one_values))
            .then((self.algorithm as *const Algorithm).cmp(&(other.algorithm as *const Algorithm)))
    }
}

impl Hash for PublicKey {
    #[allow(trivial_casts)]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.zero_values.hash(state);
        self.one_values.hash(state);
        (self.algorithm as *const Algorithm).hash(state);
    }
}

/// A one-time signing private key
#[derive(Clone, Debug)]
pub struct PrivateKey {
    // For a n bits hash function: (n * n/8 bytes) for zero_values and one_values
    zero_values: Vec<Vec<u8>>,
    one_values: Vec<Vec<u8>>,
    algorithm: &'static Algorithm,
    used: bool,
}

impl From<PublicKey> for Vec<u8> {
    fn from(original: PublicKey) -> Vec<u8> {
        original.to_bytes()
    }
}

impl PublicKey {
    /// Intializes a public key with a byte vector.
    /// Returns `None` if it couldn't parse the provided data.
    pub fn from_vec(vec: Vec<u8>, algorithm: &'static Algorithm) -> Option<PublicKey> {
        let size = vec.len();
        let hash_output_size = algorithm.output_len;
        if size != (hash_output_size * hash_output_size * 8 * 2) {
            return None;
        }

        let hsize = size / 2;
        let zeros_len = hsize / hash_output_size;
        let mut zero_values = Vec::with_capacity(zeros_len);
        let mut one_values = Vec::with_capacity(zeros_len);
        // TODO: switch from `filter` to `step_by` when stable.
        for (i, j) in (0..(hsize))
            .filter(|x| x % hash_output_size == 0)
            .zip((hash_output_size..(hsize + 1)).filter(|x| x % hash_output_size == 0))
        {
            zero_values.push(vec[i..j].to_vec());
            one_values.push(vec[(hsize + i)..(hsize + j)].to_vec());
        }

        Some(PublicKey {
            zero_values,
            one_values,
            algorithm,
        })
    }

    /// Serializes a public key into a byte vector
    pub fn to_bytes(&self) -> Vec<u8> {
        // num fields * length fields * length secret
        let len = 2 * (8 * self.algorithm.output_len) * self.algorithm.output_len;
        self.zero_values.iter().chain(self.one_values.iter()).fold(
            Vec::with_capacity(len),
            |mut acc, i| {
                acc.extend_from_slice(i);
                acc
            },
        )
    }

    /// Verifies that the signature of the data is correctly signed with the given key
    pub fn verify_signature(&self, signature: &LamportSignatureData, data: &[u8]) -> bool {
        if signature.len() != self.algorithm.output_len * 8 {
            return false;
        }
        let hash = digest(&self.algorithm, data);

        let mut x = 1;
        for (i, byte) in hash.as_ref().iter().enumerate() {
            for j in 0..8 {
                let offset = i * 8 + j;
                let hashed_value = digest(&self.algorithm, &signature[offset][..]);

                if byte_is_nonzero(byte & (1 << j)) == 1 {
                    x &= slices_equal(&hashed_value.as_ref(), &self.one_values[offset][..]);
                } else {
                    x &= slices_equal(&hashed_value.as_ref(), &self.zero_values[offset][..]);
                }
            }
        }

        x == 1
    }
}

impl PrivateKey {
    /// Generates a new random one-time signing key. This method can panic if OS RNG fails
    pub fn new(algorithm: &'static Algorithm) -> PrivateKey {
        let mut rng = match OsRng::new() {
            Ok(g) => g,
            Err(e) => panic!("Failed to obtain OS RNG: {}", e),
        };
        let generate_bit_hash_values = |rng: &mut OsRng| -> Vec<Vec<u8>> {
            let buffer_byte = vec![0u8; algorithm.output_len];
            let mut buffer = vec![buffer_byte; algorithm.output_len * 8];

            for hash in &mut buffer {
                // TODO: Upgrade to `try_fill_bytes` when that hits
                // stable in `rand` (probably 0.5).
                rng.fill_bytes(hash)
            }

            buffer
        };

        let zero_values = generate_bit_hash_values(&mut rng);
        let one_values = generate_bit_hash_values(&mut rng);

        PrivateKey {
            zero_values,
            one_values,
            algorithm,
            used: false,
        }
    }

    /// Returns the public key associated with this private key
    pub fn public_key(&self) -> PublicKey {
        let hash_values = |x: &Vec<Vec<u8>>| -> Vec<Vec<u8>> {
            let buffer_byte = vec![0u8; self.algorithm.output_len];
            let mut buffer = vec![buffer_byte; self.algorithm.output_len * 8];

            for i in 0..self.algorithm.output_len * 8 {
                let hash = digest(&self.algorithm, &x[i][..]);
                buffer[i] = Vec::from(hash.as_ref());
            }

            buffer
        };

        let hashed_zero_values = hash_values(&self.zero_values);
        let hashed_one_values = hash_values(&self.one_values);

        PublicKey {
            zero_values: hashed_zero_values,
            one_values: hashed_one_values,
            algorithm: self.algorithm,
        }
    }

    /// Signs the data with the private key and returns the result if successful.
    /// If unsuccesful, an explanation string is returned
    pub fn sign(&mut self, data: &[u8]) -> Result<LamportSignatureData, &'static str> {
        if self.used {
            return Err("Attempting to sign more than once.");
        }

        let hash = digest(&self.algorithm, data);
        let data_hash = hash.as_ref();

        let signature_len = data_hash.len() * 8;
        let mut signature = Vec::with_capacity(signature_len);

        for (i, byte) in data_hash.iter().enumerate() {
            for j in 0..8 {
                let offset = i * 8 + j;
                if (byte & (1 << j)) > 0 {
                    // Bit is 1
                    signature.push(self.one_values[offset].clone());
                } else {
                    // Bit is 0
                    signature.push(self.zero_values[offset].clone());
                }
            }
        }
        self.used = true;
        Ok(signature)
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        let zeroize_vector = |vector: &mut Vec<Vec<u8>>| {
            for v2 in vector.iter_mut() {
                for byte in v2.iter_mut() {
                    *byte = 0;
                }
            }
        };

        zeroize_vector(&mut self.zero_values);
        zeroize_vector(&mut self.one_values);
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &PrivateKey) -> bool {
        if self.algorithm != other.algorithm {
            return false;
        }
        // NOTE: The `zero_values` and `one_values` need not be of the
        // the same length (and maybe this should change).
        let zero_size = self.zero_values.len();
        let one_size = self.one_values.len();
        if zero_size != other.zero_values.len() || one_size != other.one_values.len() {
            return false;
        }

        let mut x = 1;
        for i in 0..zero_size {
            x &= slices_equal(&self.zero_values[i][..], &other.zero_values[i][..]);
        }
        for i in 0..one_size {
            x &= slices_equal(&self.one_values[i][..], &other.one_values[i][..]);
        }
        x == 1
    }
}

impl Eq for PrivateKey {}

impl PartialOrd for PrivateKey {
    fn partial_cmp(&self, other: &PrivateKey) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PrivateKey {
    // ⚠️ This is not a constant-time implementation
    fn cmp(&self, other: &PrivateKey) -> Ordering {
        self.one_values
            .cmp(&other.one_values)
            .then(self.zero_values.cmp(&other.zero_values))
    }
}

#[cfg(test)]
pub mod tests;
