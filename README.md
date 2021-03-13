# Certify

Create client certificates for your TLS app.

```rust
let ca = load_ca(ca_cert_pem, ca_key_pem)?;
let (cert_pem, key_pem) = generate_cert(&ca, &[], "US", "web", "abcd1234", true, 365)?;
```

## License

`prost-helper` is distributed under the terms of MIT.

See [LICENSE](LICENSE.md) for details.

Copyright 2021 Tyr Chen
