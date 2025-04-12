# Certify

Create client certificates for your TLS app.

## Usage

```rust
// Generate a CA certificate and key
let (ca_pem, ca_key) =
    generate_ca("US", "Acme, Inc.", "acme", CertSigAlgo::ED25519, None, None)?;

// Load existing CA
let ca = CA::load(&ca_pem, &ca_key)?;

// Generate a server certificate
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

// Generate a client certificate
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
```

## License

`certify` is distributed under the terms of MIT.

See [LICENSE](LICENSE.md) for details.

Copyright 2021 Tyr Chen
