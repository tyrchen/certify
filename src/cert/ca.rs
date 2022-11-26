use rcgen::{Certificate, CertificateParams, KeyPair};

use super::Cert;
use crate::CertifyError;

pub struct CA {
    cert: Certificate,
    data: Option<Vec<u8>>,
}

impl CA {
    pub fn load(ca_cert: &str, ca_key: &str) -> Result<Self, CertifyError> {
        let key = KeyPair::from_pem(ca_key)?;
        let params = CertificateParams::from_ca_cert_pem(ca_cert, key)?;
        let ca_data = pem::parse(ca_cert)?.contents;
        let mut result = Self::from_params(params)?;
        result.data = Some(ca_data);
        Ok(result)
    }

    pub fn from_params(params: CertificateParams) -> Result<Self, CertifyError> {
        Ok(CA {
            cert: Certificate::from_params(params)?,
            data: None,
        })
    }

    pub fn sign_cert(&self, cert: &Cert) -> Result<(String, String), CertifyError> {
        let cert_pem = cert.0.serialize_pem_with_signer(&self.cert)?;
        let key_pem = cert.0.serialize_private_key_pem();
        Ok((cert_pem, key_pem))
    }

    pub fn serialize_der(&self) -> Result<Vec<u8>, CertifyError> {
        match &self.data {
            Some(data) => Ok(data.to_owned()),
            None => Ok(self.cert.serialize_der()?),
        }
    }

    pub fn serialize_pem(&self) -> Result<String, CertifyError> {
        let p = pem::Pem {
            tag: "CERTIFICATE".to_string(),
            contents: self.serialize_der()?,
        };
        Ok(pem::encode(&p))
    }

    pub fn serialize_private_key_pem(&self) -> String {
        self.cert.serialize_private_key_pem()
    }
}
