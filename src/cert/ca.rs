use super::Cert;
use crate::CertifyError;
use rcgen::{CertificateParams, KeyPair};

pub struct CA {
    cert: Cert,
    data: Option<Vec<u8>>,
}

impl CA {
    pub fn load(ca_cert: &str, ca_key: &str) -> Result<Self, CertifyError> {
        let key = KeyPair::from_pem(ca_key)?;
        let params = CertificateParams::from_ca_cert_pem(ca_cert)?;
        let ca_data = pem::parse(ca_cert)?.into_contents();
        let mut result = Self::from_params(params, key)?;
        result.data = Some(ca_data);
        Ok(result)
    }

    pub fn from_params(params: CertificateParams, keypair: KeyPair) -> Result<Self, CertifyError> {
        let cert = Cert::from_params(params, keypair)?;
        Ok(CA { cert, data: None })
    }

    pub fn sign_cert(&self, cert: &Cert) -> Result<(String, String), CertifyError> {
        let keypair = &cert.keypair;

        let signed_cert =
            cert.inner
                .params()
                .clone()
                .signed_by(keypair, &self.cert.inner, &self.cert.keypair)?;

        let cert_pem = signed_cert.pem();
        let key_pem = keypair.serialize_pem();

        Ok((cert_pem, key_pem))
    }

    pub fn serialize_der(&self) -> Result<Vec<u8>, CertifyError> {
        match &self.data {
            Some(data) => Ok(data.to_owned()),
            None => Ok(self.cert.inner.der().to_vec()),
        }
    }

    pub fn serialize_pem(&self) -> Result<String, CertifyError> {
        let p = pem::Pem::new("CERTIFICATE", self.serialize_der()?);
        Ok(pem::encode(&p))
    }

    pub fn serialize_private_key_pem(&self) -> String {
        self.cert.keypair.serialize_pem()
    }
}
