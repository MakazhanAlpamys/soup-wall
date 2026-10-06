//! Legacy operations unavailable through the initial alternate-provider adapters.

pub mod aes_cbc {
    use crate::algorithm::{AesKeySize, CipherAlgorithm};
    use crate::backend::{random_bytes, require_supported, Operation};
    use crate::error::{Error, Result};

    pub fn encrypt(size: AesKeySize, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let operation = Operation::Encrypt(CipherAlgorithm::AesCbc(size));
        require_supported(operation)?;
        validate_key(size, key)?;
        let iv = random_bytes(16)?;
        let ciphertext = aws_encrypt(key, &iv, plaintext)?;
        let mut output = Vec::with_capacity(16 + ciphertext.len());
        output.extend_from_slice(&iv);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    pub fn decrypt(size: AesKeySize, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let operation = Operation::Decrypt(CipherAlgorithm::AesCbc(size));
        require_supported(operation)?;
        validate_key(size, key)?;
        let opaque = || Error::Crypto("AES-CBC decrypt failed".into());
        if ciphertext.len() < 32 || !(ciphertext.len() - 16).is_multiple_of(16) {
            return Err(opaque());
        }
        let (iv, ciphertext) = ciphertext.split_at(16);
        aws_decrypt(key, iv, ciphertext).map_err(|_| opaque())
    }

    fn validate_key(size: AesKeySize, key: &[u8]) -> Result<()> {
        if key.len() != size.key_len() {
            return Err(Error::Crypto(format!(
                "AES key must be {} bytes, got {}",
                size.key_len(),
                key.len()
            )));
        }
        Ok(())
    }

    fn aws_key(key: &[u8]) -> Result<aws_lc_rs::cipher::UnboundCipherKey> {
        use aws_lc_rs::cipher::{UnboundCipherKey, AES_128, AES_192, AES_256};
        let algorithm = match key.len() {
            16 => &AES_128,
            24 => &AES_192,
            32 => &AES_256,
            _ => return Err(Error::Crypto("invalid AES key length".into())),
        };
        UnboundCipherKey::new(algorithm, key)
            .map_err(|_| Error::Crypto("AWS-LC AES key setup failed".into()))
    }

    fn aws_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        use aws_lc_rs::cipher::{EncryptingKey, EncryptionContext};
        use aws_lc_rs::iv::FixedLength;
        let iv: [u8; 16] = iv
            .try_into()
            .map_err(|_| Error::Crypto("invalid AES-CBC IV".into()))?;
        let key = EncryptingKey::cbc(aws_key(key)?)
            .map_err(|_| Error::Crypto("AWS-LC AES-CBC setup failed".into()))?;
        let mut output = xmlenc_pad(plaintext, 16);
        key.less_safe_encrypt(&mut output, EncryptionContext::Iv128(FixedLength::from(iv)))
            .map_err(|_| Error::Crypto("AWS-LC AES-CBC encryption failed".into()))?;
        Ok(output)
    }

    fn aws_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        use aws_lc_rs::cipher::{DecryptingKey, DecryptionContext};
        use aws_lc_rs::iv::FixedLength;
        let iv: [u8; 16] = iv
            .try_into()
            .map_err(|_| Error::Crypto("invalid AES-CBC IV".into()))?;
        let key = DecryptingKey::cbc(aws_key(key)?)
            .map_err(|_| Error::Crypto("AWS-LC AES-CBC setup failed".into()))?;
        let mut output = ciphertext.to_vec();
        let plaintext = key
            .decrypt(&mut output, DecryptionContext::Iv128(FixedLength::from(iv)))
            .map_err(|_| Error::Crypto("AWS-LC AES-CBC decryption failed".into()))?;
        xmlenc_unpad(plaintext, 16)
    }

    fn xmlenc_pad(input: &[u8], block_size: usize) -> Vec<u8> {
        let padding = block_size - input.len() % block_size;
        let mut output = Vec::with_capacity(input.len() + padding);
        output.extend_from_slice(input);
        output.extend(std::iter::repeat_n(padding as u8, padding));
        output
    }

    fn xmlenc_unpad(input: &[u8], block_size: usize) -> Result<Vec<u8>> {
        let padding = usize::from(
            *input
                .last()
                .ok_or_else(|| Error::Crypto("AES-CBC decryption failed".into()))?,
        );
        if padding == 0 || padding > block_size || padding > input.len() {
            return Err(Error::Crypto("AES-CBC decryption failed".into()));
        }
        Ok(input[..input.len() - padding].to_vec())
    }
}

pub mod dh {
    use crate::backend::Operation;
    use crate::error::{Error, Result};

    pub fn compute(
        _other_public: &[u8],
        _my_private: &[u8],
        _p: &[u8],
        _q: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        Err(Error::unsupported(
            Operation::DhAgreement,
            "finite-field DH",
        ))
    }
}
