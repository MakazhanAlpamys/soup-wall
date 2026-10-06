//! Provider-neutral public algorithm parameters.

/// Public finite-field Diffie-Hellman parameters and public key.
///
/// The private exponent, when present, remains inside [`crate::SoftwareKey`]
/// and is never exposed through this value.
#[derive(Clone, PartialEq, Eq)]
pub struct DhParameters {
    modulus: Vec<u8>,
    generator: Vec<u8>,
    subgroup_order: Option<Vec<u8>>,
    public_key: Vec<u8>,
}

impl std::fmt::Debug for DhParameters {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DhParameters")
            .field("modulus_len", &self.modulus.len())
            .field("generator_len", &self.generator.len())
            .field(
                "subgroup_order_len",
                &self.subgroup_order.as_ref().map(Vec::len),
            )
            .field("public_key_len", &self.public_key.len())
            .finish()
    }
}

impl DhParameters {
    #[cfg(feature = "rustcrypto")]
    pub(crate) fn new(
        modulus: &[u8],
        generator: &[u8],
        subgroup_order: Option<&[u8]>,
        public_key: &[u8],
    ) -> Self {
        Self {
            modulus: modulus.to_vec(),
            generator: generator.to_vec(),
            subgroup_order: subgroup_order.map(<[u8]>::to_vec),
            public_key: public_key.to_vec(),
        }
    }

    #[must_use]
    pub fn modulus(&self) -> &[u8] {
        &self.modulus
    }

    #[must_use]
    pub fn generator(&self) -> &[u8] {
        &self.generator
    }

    #[must_use]
    pub fn subgroup_order(&self) -> Option<&[u8]> {
        self.subgroup_order.as_deref()
    }

    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}
