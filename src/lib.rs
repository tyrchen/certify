mod cert;
mod error;

use cert::{Params, CA};

pub use error::CertifyError;

/// load CA with cert string and key string
pub fn load_ca(cert: &str, key: &str) -> Result<CA, CertifyError> {
    CA::from_pem(cert, key)
}

/// Generate CA cert
pub fn generate_ca<'a>(
    domains: impl AsRef<[&'a str]>,
    country: &str,
    org: &str,
    cn: &str,
    days: Option<i64>,
) -> Result<(String, String), CertifyError> {
    let params = Params::new(domains, &[], country, org, cn, days);
    let ca = params.ca_cert()?;
    Ok((ca.serialize_pem().unwrap(), ca.serialize_private_key_pem()))
}

/// generate cert signed by the CA
pub fn generate_cert<'a>(
    ca: &CA,
    domains: impl AsRef<[&'a str]>,
    country: &str,
    org: &str,
    cn: &str,
    is_client: bool,
    days: Option<i64>,
) -> Result<(String, String), CertifyError> {
    let params = Params::new(domains, &[], country, org, cn, days);

    let cert = if is_client {
        params.client_cert()?
    } else {
        params.server_cert()?
    };
    let (cert_pem, key_pem) = ca.sign_cert(&cert)?;
    Ok((cert_pem, key_pem))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ca_cert_should_work() -> Result<(), CertifyError> {
        let (cert, key) = gen_ca()?;
        let ca = load_ca(&cert, &key)?;
        let cert1 = ca.serialize_pem()?;

        assert_eq!(cert, cert1);
        Ok(())
    }

    #[test]
    fn generate_server_cert_with_ca_should_work() -> Result<(), CertifyError> {
        let (cert, key) = gen_ca()?;
        let ca = load_ca(&cert, &key)?;
        let (server_cert, server_key) = generate_cert(
            &ca,
            &["app.domain.com"],
            "US",
            "Domain Domain Inc.",
            "API Server",
            false,
            Some(365),
        )?;

        println!("{}\n{}", server_cert, server_key);

        Ok(())
    }

    #[test]
    fn generate_client_cert_with_ca_should_work() -> Result<(), CertifyError> {
        let (cert, key) = gen_ca()?;
        let ca = load_ca(&cert, &key)?;
        let (client_cert, client_key) = generate_cert(
            &ca,
            &["app.domain.com"],
            "CA",
            "macos",
            "awesome_device_id",
            true,
            Some(365),
        )?;

        println!("{}\n{}", client_cert, client_key);

        Ok(())
    }

    fn gen_ca() -> Result<(String, String), CertifyError> {
        generate_ca(
            &["domain.com"],
            "US",
            "Domain Domain Inc.",
            "Domain CA",
            None,
        )
    }
}
