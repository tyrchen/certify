use anyhow::Result;
use certify::{generate_ca, generate_cert, CertSigAlgo, CA};

fn main() -> Result<()> {
    let (ca_pem, ca_key) =
        generate_ca("US", "Acme, Inc.", "acme", CertSigAlgo::ED25519, None, None)?;
    println!("CA: {}", ca_pem);
    println!("CA Key: {}", ca_key);

    // load ca
    let ca = CA::load(&ca_pem, &ca_key)?;

    // sign a server cert
    let (server_pem, server_key) = generate_cert(
        &ca,
        vec!["server.acme.com"],
        "US",
        "Dev",
        "Dev Server",
        CertSigAlgo::ED25519,
        None,
        false,
        None,
    )?;
    println!("Server Cert: {}", server_pem);
    println!("Server Key: {}", server_key);

    // sign a client cert
    let (client_pem, client_key) = generate_cert(
        &ca,
        vec!["client.acme.com"],
        "US",
        "Dev",
        "Dev Client",
        CertSigAlgo::ED25519,
        None,
        true,
        None,
    )?;
    println!("Client Cert: {}", client_pem);
    println!("Client Key: {}", client_key);

    Ok(())
}
