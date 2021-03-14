mod cert;
mod error;

pub use cert::{CertInfo, CA};
pub use error::CertifyError;

// re-exports
pub use rcgen::KeyPair;

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
    pem_str: Option<&str>,
    days: Option<i64>,
) -> Result<(String, String), CertifyError> {
    let params = CertInfo::new(domains, &[], country, org, cn, days);
    let keypair = match pem_str {
        Some(v) => Some(KeyPair::from_pem(v)?),
        None => None,
    };
    let ca = params.ca_cert(keypair)?;
    Ok((ca.serialize_pem().unwrap(), ca.serialize_private_key_pem()))
}

/// generate cert signed by the CA
pub fn generate_cert<'a>(
    ca: &CA,
    domains: impl AsRef<[&'a str]>,
    country: &str,
    org: &str,
    cn: &str,
    pem_str: Option<&str>,
    is_client: bool,
    days: Option<i64>,
) -> Result<(String, String), CertifyError> {
    let params = CertInfo::new(domains, &[], country, org, cn, days);
    let keypair = match pem_str {
        Some(v) => Some(KeyPair::from_pem(v)?),
        None => None,
    };
    let cert = if is_client {
        params.client_cert(keypair)?
    } else {
        params.server_cert(keypair)?
    };
    let (cert_pem, key_pem) = ca.sign_cert(&cert)?;
    Ok((cert_pem, key_pem))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ca_cert_should_work() -> Result<(), CertifyError> {
        let (cert, key) = gen_ca(None)?;
        let ca = load_ca(&cert, &key)?;
        let cert1 = ca.serialize_pem()?;

        assert_eq!(cert, cert1);
        Ok(())
    }

    #[test]
    fn generate_ca_cert_with_existing_key_should_work() -> Result<(), CertifyError> {
        let key_pem = include_str!("fixtures/ca_key.pem");
        let ca_pem = include_str!("fixtures/ca_cert.pem");
        let (cert, key) = gen_ca(Some(key_pem))?;
        let ca = load_ca(&cert, &key)?;
        let cert1 = ca.serialize_pem()?;

        assert_eq!(cert, cert1);
        assert_eq!(key_pem, key);

        let ca = load_ca(ca_pem, &key)?;
        let cert2 = ca.serialize_pem()?;

        assert_eq!(ca_pem, cert2);

        Ok(())
    }

    #[test]
    fn generate_server_cert_with_ca_should_work() -> Result<(), CertifyError> {
        let (cert, key) = gen_ca(None)?;
        let ca = load_ca(&cert, &key)?;
        let (server_cert, server_key) = generate_cert(
            &ca,
            &["app.domain.com"],
            "US",
            "Domain Domain Inc.",
            "API Server",
            None,
            false,
            Some(365),
        )?;

        println!("{}\n{}", server_cert, server_key);

        Ok(())
    }

    #[test]
    fn generate_server_cert_with_existing_ca_and_key_should_work() -> Result<(), CertifyError> {
        let key_pem = include_str!("fixtures/ca_key.pem");
        let ca_pem = include_str!("fixtures/ca_cert.pem");
        let server_key_pem = include_str!("fixtures/server_key.pem");

        let ca = load_ca(&ca_pem, &key_pem)?;
        let (server_cert, server_key) = generate_cert(
            &ca,
            &["app.domain.com"],
            "US",
            "Domain Domain Inc.",
            "API Server",
            Some(server_key_pem),
            false,
            Some(365),
        )?;

        assert_eq!(&server_key, server_key_pem);

        println!("{}\n{}", server_cert, server_key);

        Ok(())
    }
    #[test]
    fn generate_client_cert_with_ca_should_work() -> Result<(), CertifyError> {
        let (cert, key) = gen_ca(None)?;
        let ca = load_ca(&cert, &key)?;
        let (client_cert, client_key) = generate_cert(
            &ca,
            &["app.domain.com"],
            "CA",
            "macos",
            "awesome_device_id",
            None,
            true,
            Some(365),
        )?;

        println!("{}\n{}", client_cert, client_key);

        Ok(())
    }

    #[test]
    fn generate_client_cert_with_existing_ca_and_key_should_work() -> Result<(), CertifyError> {
        let key_pem = include_str!("fixtures/ca_key.pem");
        let ca_pem = include_str!("fixtures/ca_cert.pem");
        let client_key_pem = include_str!("fixtures/client_key.pem");

        let ca = load_ca(&ca_pem, &key_pem)?;

        let (client_cert, client_key) = generate_cert(
            &ca,
            &["app.domain.com"],
            "CA",
            "macos",
            "awesome_device_id",
            Some(client_key_pem),
            true,
            Some(365),
        )?;

        assert_eq!(&client_key, client_key_pem);
        println!("{}\n{}", client_cert, client_key);

        Ok(())
    }

    fn gen_ca(pem: Option<&str>) -> Result<(String, String), CertifyError> {
        generate_ca(
            &["domain.com"],
            "US",
            "Domain Domain Inc.",
            "Domain CA",
            pem,
            None,
        )
    }

    // fn write_file(name: &str, content: &str) {
    //     use std::io::Write;
    //     let mut file = std::fs::File::create(name).unwrap();
    //     file.write_all(content.as_bytes()).unwrap();
    // }
}
