use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CustomExtension, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose::*, IsCa, KeyIdMethod, KeyPair, SanType, SignatureAlgorithm,
    PKCS_ECDSA_P256_SHA256, PKCS_ED25519,
};
use std::convert::TryInto;
use std::net::IpAddr;
use time::{Duration, OffsetDateTime};

use super::CA;
use crate::CertifyError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Usage {
    None,
    Ca,
    Cert,
}

// const OID_ORG_UNIT: &[u64] = &[2, 5, 4, 11];
const OID_BASIC: &[u64] = &[2, 5, 29, 19];

const OID_KEY_USAGE: &[u64] = &[2, 5, 29, 15];

const KEY_USAGE: &[Usage] = &[
    Usage::Cert, // digitalSignature
    Usage::Cert, // nonRepudiation/contentCommitment
    Usage::Cert, // keyEncipherment
    Usage::None,
    Usage::None,
    Usage::Ca, // keyCertSign
    Usage::Ca, // cRLSign
    Usage::None,
    Usage::None,
];

pub struct Cert {
    pub(crate) inner: Certificate,
    pub(crate) keypair: KeyPair,
}

const CERT_DEFAULT_DURATION: i64 = 180; // 180 days
const CA_DEFAULT_DURATION: i64 = 10 * 365; // approx 10 years

impl Cert {
    pub fn from_params(params: CertificateParams, keypair: KeyPair) -> Result<Self, CertifyError> {
        let cert = params.self_signed(&keypair)?;
        Ok(Cert {
            inner: cert,
            keypair,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CertInfo {
    pub domain_names: Vec<String>,
    pub ip_address: Vec<IpAddr>,
    pub country: String,
    pub organization: String,
    pub common: String,
    pub days: Option<i64>,
    pub sig_algo: CertSigAlgo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertSigAlgo {
    EcDsa,
    ED25519,
}

impl CertInfo {
    pub fn new(
        domains: Vec<impl Into<String>>,
        ips: Vec<impl Into<String>>,
        country: &str,
        org: &str,
        cn: &str,
        days: Option<i64>,
        sig_algo: CertSigAlgo,
    ) -> Self {
        Self {
            domain_names: domains.into_iter().map(|d| d.into()).collect(),
            ip_address: ips
                .into_iter()
                .map(|ip| ip.into().parse().unwrap())
                .collect(),
            country: country.to_owned(),
            organization: org.to_owned(),
            common: cn.to_owned(),
            days,
            sig_algo,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertType {
    Client,
    Server,
    CA,
}

impl CertInfo {
    fn build_cert_params(&self, cert_type: CertType) -> CertificateParams {
        let default_days = if cert_type == CertType::CA {
            CA_DEFAULT_DURATION
        } else {
            CERT_DEFAULT_DURATION
        };
        let days = self.days.unwrap_or(default_days);

        let not_before = OffsetDateTime::now_utc();

        let not_after = not_before + Duration::days(days);

        let mut subject_alt_names = vec![];
        for dns in self.domain_names.iter() {
            subject_alt_names.push(SanType::DnsName(dns.clone().try_into().unwrap()));
        }
        for ip in self.ip_address.iter() {
            subject_alt_names.push(SanType::IpAddress(*ip));
        }
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CountryName, &self.country);
        distinguished_name.push(DnType::OrganizationName, &self.organization);
        distinguished_name.push(DnType::CommonName, &self.common);

        let mut params = CertificateParams::default();
        params.not_before = not_before;
        params.not_after = not_after;
        params.subject_alt_names = subject_alt_names;
        params.distinguished_name = distinguished_name;

        // WTF: turned out we should not use this to satisfy openssl
        // params.use_authority_key_identifier_extension = true;
        params.key_identifier_method = KeyIdMethod::Sha512;
        match cert_type {
            CertType::CA => {
                params.extended_key_usages = vec![Any];
                params.is_ca = IsCa::Ca(BasicConstraints::Constrained(16));
                params.custom_extensions.push(CertInfo::key_usage(true));
            }
            CertType::Client => {
                params.extended_key_usages = vec![ClientAuth];
                params.custom_extensions.push(CertInfo::not_ca());
                params.custom_extensions.push(CertInfo::key_usage(false));
            }
            CertType::Server => {
                params.extended_key_usages = vec![ServerAuth];
                params.custom_extensions.push(CertInfo::not_ca());
                params.custom_extensions.push(CertInfo::key_usage(false));
            }
        }

        params
    }

    pub fn ca_cert(&self, keypair: KeyPair) -> Result<CA, CertifyError> {
        let mut params = self.build_cert_params(CertType::CA);
        params.extended_key_usages = vec![];
        CA::from_params(params, keypair)
    }

    pub fn client_cert(&self, keypair: KeyPair) -> Result<Cert, CertifyError> {
        let params = self.build_cert_params(CertType::Client);
        Cert::from_params(params, keypair)
    }

    pub fn server_cert(&self, keypair: KeyPair) -> Result<Cert, CertifyError> {
        let params = self.build_cert_params(CertType::Server);
        Cert::from_params(params, keypair)
    }

    fn key_usage(ca: bool) -> CustomExtension {
        let der = yasna::construct_der(|writer| {
            writer.write_bitvec(
                &KEY_USAGE
                    .iter()
                    .map(|u| *u == if ca { Usage::Ca } else { Usage::Cert })
                    .collect(),
            );
        });

        let mut key_usage = CustomExtension::from_oid_content(OID_KEY_USAGE, der);
        key_usage.set_criticality(true);
        key_usage
    }

    fn not_ca() -> CustomExtension {
        let der = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_bool(false);
            });
        });

        CustomExtension::from_oid_content(OID_BASIC, der)
    }
}

impl From<CertSigAlgo> for &'static SignatureAlgorithm {
    fn from(algo: CertSigAlgo) -> Self {
        match algo {
            CertSigAlgo::EcDsa => &PKCS_ECDSA_P256_SHA256,
            CertSigAlgo::ED25519 => &PKCS_ED25519,
        }
    }
}
