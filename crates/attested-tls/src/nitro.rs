//! AWS Nitro evidence validation for certificate-bound attested TLS.
//!
//! The certificate transport is deliberately independent of the Nitro NSM API:
//! the enclave supplies a signed document and the peer validates it here.  This
//! keeps the verifier usable by ordinary hosts and makes the policy explicit.

#![deny(clippy::cast_lossless)]

use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime},
};

use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use coset::{CborSerializable as _, CoseSign1, TaggedCborSerializable as _};
use rcgen::{
    CertificateParams, CustomExtension, KeyPair, PKCS_ECDSA_P256_SHA256, PublicKeyData as _,
};
use ring::signature::{ECDSA_P384_SHA384_FIXED, UnparsedPublicKey};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        verify_server_name,
    },
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    server::ParsedCertificate,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use x509_parser::{certificate::X509Certificate, parse_x509_certificate};

/// Private X.509 extension carrying the raw, COSE_Sign1-encoded Nitro document.
///
/// This is a deployment-owned private enterprise arc. The extension is non-critical:
/// clients that do not implement attested TLS reject the self-signed leaf in the
/// usual way, while attested clients require this extension.
pub const NITRO_ATTESTATION_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 57264, 1, 1];

/// SHA-256 fingerprint of AWS Nitro Enclaves Root-G1, published by AWS.
const AWS_NITRO_ROOT_G1_SHA256: [u8; 32] = [
    0x64, 0x1a, 0x03, 0x21, 0xa3, 0xe2, 0x44, 0xef, 0xe4, 0x56, 0x46, 0x31, 0x95, 0xd6, 0x06, 0x31,
    0x7e, 0xd7, 0xcd, 0xcc, 0x3c, 0x17, 0x56, 0xe0, 0x98, 0x93, 0xf3, 0xc6, 0x8f, 0x79, 0xbb, 0x5b,
];

/// Complete allowlist for a particular enclave deployment.
///
/// Every locked PCR in the document must be present, and every configured PCR
/// must be present in the document. More than one value per PCR supports a
/// controlled rollout, but never turns an omitted PCR into a wildcard.
#[derive(Clone, Debug, Default)]
pub struct NitroPolicy {
    pub pcrs: BTreeMap<usize, Vec<Vec<u8>>>,
    pub max_age: Duration,
    pub module_id: Option<String>,
}

impl NitroPolicy {
    /// Reject policies that would silently accept a document without PCRs.
    pub fn validate(&self) -> Result<(), NitroError> {
        if self.pcrs.is_empty() || self.pcrs.values().any(Vec::is_empty) {
            return Err(NitroError::IncompletePolicy);
        }
        Ok(())
    }
}

/// Values supplied by the client before the TLS handshake and verified from
/// the certificate extension during that handshake.
#[derive(Clone, Debug)]
pub struct NitroBinding<'a> {
    /// Application-owned domain separation and protocol identity.
    pub context: &'a [u8],
    pub nonce: &'a [u8],
    pub tls_spki: &'a [u8],
}

/// Enclave-side source of a Nitro document. Implementations must call the NSM
/// only after the client nonce and newly-generated TLS public key are known.
pub trait NitroAttester: Send + Sync + 'static {
    fn attest(
        &self,
        nonce: &[u8],
        tls_spki: &[u8],
        user_data: &[u8],
    ) -> Result<Vec<u8>, NitroError>;
}

/// Generate an enclave-held P-256 TLS key and a single-use self-signed
/// certificate with a Nitro document in its extension.
///
/// This must be called once for each nonce preface; reusing certificates would
/// weaken freshness to certificate lifetime.
pub fn server_config_for_nonce(
    attester: &dyn NitroAttester,
    context: &[u8],
    nonce: &[u8],
    subject: &str,
    provider: Arc<CryptoProvider>,
) -> Result<rustls::ServerConfig, NitroError> {
    if nonce.len() < 32 {
        return Err(NitroError::NonceTooShort);
    }
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|_| NitroError::CertificateGeneration)?;
    let tls_spki = key_pair.subject_public_key_info();
    let user_data = binding_user_data(NitroBinding { context, nonce, tls_spki: &tls_spki });
    let document = attester.attest(nonce, &tls_spki, &user_data)?;
    if document.len() > 16 * 1024 {
        return Err(NitroError::DocumentTooLarge);
    }

    let mut parameters = CertificateParams::new(vec![subject.to_owned()])
        .map_err(|_| NitroError::CertificateGeneration)?;
    parameters
        .custom_extensions
        .push(CustomExtension::from_oid_content(NITRO_ATTESTATION_OID, document));
    let certificate =
        parameters.self_signed(&key_pair).map_err(|_| NitroError::CertificateGeneration)?;
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    let certificate = CertificateDer::from(certificate.der().to_vec());

    rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| NitroError::CertificateGeneration)?
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)
        .map_err(|_| NitroError::CertificateGeneration)
}

/// Rustls verifier for a single-use Nitro-attested self-signed certificate.
#[derive(Debug)]
pub struct NitroServerVerifier {
    policy: NitroPolicy,
    context: Vec<u8>,
    nonce: Vec<u8>,
    provider: Arc<CryptoProvider>,
    trust_anchor_fingerprint: [u8; 32],
}

impl NitroServerVerifier {
    pub fn new(
        policy: NitroPolicy,
        context: Vec<u8>,
        nonce: Vec<u8>,
        provider: Arc<CryptoProvider>,
    ) -> Result<Self, NitroError> {
        policy.validate()?;
        if nonce.len() < 32 {
            return Err(NitroError::NonceTooShort);
        }
        Ok(Self {
            policy,
            context,
            nonce,
            provider,
            trust_anchor_fingerprint: AWS_NITRO_ROOT_G1_SHA256,
        })
    }

    fn certificate_extension<'a>(
        certificate: &'a X509Certificate<'a>,
    ) -> Result<&'a [u8], rustls::Error> {
        let oid = x509_parser::oid_registry::Oid::from(NITRO_ATTESTATION_OID)
            .map_err(|_| rustls::Error::General("invalid Nitro attestation OID".into()))?;
        certificate
            .get_extension_unique(&oid)
            .map_err(|_| rustls::Error::General("duplicate Nitro attestation extension".into()))?
            .map(|extension| extension.value)
            .ok_or_else(|| rustls::Error::General("missing Nitro attestation extension".into()))
    }
}

impl ServerCertVerifier for NitroServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if !intermediates.is_empty() {
            return Err(rustls::Error::General(
                "Nitro attested TLS leaf must be self-signed".into(),
            ));
        }
        let certificate = parse_x509_certificate(end_entity.as_ref())
            .map(|(_, certificate)| certificate)
            .map_err(|_| rustls::Error::General("invalid TLS certificate".into()))?;
        if certificate.subject() != certificate.issuer()
            || certificate.verify_signature(None).is_err()
        {
            return Err(rustls::Error::General("invalid self-signed TLS certificate".into()));
        }
        verify_cert_unix_time(&certificate, now)?;
        verify_server_name(&ParsedCertificate::try_from(end_entity)?, server_name)?;
        let evidence = Self::certificate_extension(&certificate)?;
        verify_document_with_trust_anchor(
            evidence,
            &self.policy,
            NitroBinding {
                context: &self.context,
                nonce: &self.nonce,
                tls_spki: certificate.public_key().raw,
            },
            SystemTime::UNIX_EPOCH + Duration::from_secs(now.as_secs()),
            self.trust_anchor_fingerprint,
        )
        .map_err(|error| {
            rustls::Error::General(format!("Nitro attestation verification failed: {error}"))
        })?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Returns the exact `user_data` passed to the NSM for a TLS key and nonce.
pub fn binding_user_data(binding: NitroBinding<'_>) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update((binding.context.len() as u64).to_be_bytes());
    digest.update(binding.context);
    digest.update((binding.nonce.len() as u64).to_be_bytes());
    digest.update(binding.nonce);
    digest.update((binding.tls_spki.len() as u64).to_be_bytes());
    digest.update(binding.tls_spki);
    digest.finalize().into()
}

/// Verify AWS's COSE signature, certificate chain, complete PCR policy, fresh
/// client nonce, and the SPKI/user-data channel bindings.
pub fn verify_document(
    encoded: &[u8],
    policy: &NitroPolicy,
    binding: NitroBinding<'_>,
    now: SystemTime,
) -> Result<AttestationDoc, NitroError> {
    verify_document_with_trust_anchor(encoded, policy, binding, now, AWS_NITRO_ROOT_G1_SHA256)
}

fn verify_document_with_trust_anchor(
    encoded: &[u8],
    policy: &NitroPolicy,
    binding: NitroBinding<'_>,
    now: SystemTime,
    trust_anchor_fingerprint: [u8; 32],
) -> Result<AttestationDoc, NitroError> {
    policy.validate()?;
    if encoded.len() > 16 * 1024 {
        return Err(NitroError::DocumentTooLarge);
    }

    let cose = CoseSign1::from_tagged_slice(encoded)
        .or_else(|_| CoseSign1::from_slice(encoded))
        .map_err(|_| NitroError::MalformedCose)?;
    let payload = cose.payload.as_deref().ok_or(NitroError::MissingPayload)?;
    let document =
        AttestationDoc::from_binary(payload).map_err(|_| NitroError::MalformedDocument)?;
    let signing_key = verify_certificate_chain(&document, now, trust_anchor_fingerprint)?;
    cose.verify_signature(&[], |signature, signed| {
        UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, signing_key)
            .verify(signed, signature)
            .map_err(|_| NitroError::InvalidCoseSignature)
    })?;

    if !document.nonce.as_ref().is_some_and(|nonce| nonce.as_slice() == binding.nonce) {
        return Err(NitroError::NonceMismatch);
    }
    if !document.public_key.as_ref().is_some_and(|key| key.as_slice() == binding.tls_spki) {
        return Err(NitroError::SpkiMismatch);
    }
    let expected_user_data = binding_user_data(binding);
    if !document
        .user_data
        .as_ref()
        .is_some_and(|user_data| user_data.as_slice() == expected_user_data)
    {
        return Err(NitroError::UserDataMismatch);
    }
    if let Some(module_id) = &policy.module_id
        && document.module_id != *module_id
    {
        return Err(NitroError::ModuleIdMismatch);
    }
    verify_age(document.timestamp, policy.max_age, now)?;
    verify_pcrs(&document, policy)?;
    Ok(document)
}

fn verify_age(timestamp_ms: u64, max_age: Duration, now: SystemTime) -> Result<(), NitroError> {
    let timestamp = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_millis(timestamp_ms))
        .ok_or(NitroError::TimestampInvalid)?;
    let age = now.duration_since(timestamp).map_err(|_| NitroError::TimestampInFuture)?;
    if age > max_age {
        return Err(NitroError::Stale);
    }
    Ok(())
}

fn verify_pcrs(document: &AttestationDoc, policy: &NitroPolicy) -> Result<(), NitroError> {
    if document.pcrs.len() != policy.pcrs.len() {
        return Err(NitroError::PcrSetMismatch);
    }
    for (index, allowed) in &policy.pcrs {
        let actual = document.pcrs.get(index).ok_or(NitroError::PcrSetMismatch)?;
        if !allowed.iter().any(|expected| expected.as_slice() == actual.as_ref()) {
            return Err(NitroError::PcrMismatch(*index));
        }
    }
    Ok(())
}

fn verify_certificate_chain(
    document: &AttestationDoc,
    now: SystemTime,
    trust_anchor_fingerprint: [u8; 32],
) -> Result<Vec<u8>, NitroError> {
    let leaf = parse_certificate(document.certificate.as_ref())?;
    verify_validity(&leaf, now)?;
    // Nitro serializes its CA bundle root-first: [ROOT, INTERM_1, …,
    // INTERM_N]. Build the verification path in the opposite direction.
    let (root_bytes, intermediate_bytes) =
        document.cabundle.split_first().ok_or(NitroError::MissingCaBundle)?;
    if Sha256::digest(root_bytes.as_ref()).as_ref() != trust_anchor_fingerprint {
        return Err(NitroError::UntrustedRoot);
    }
    let mut issuer = parse_certificate(root_bytes.as_ref())?;
    verify_validity(&issuer, now)?;
    if !issuer.is_ca() || issuer.verify_signature(None).is_err() {
        return Err(NitroError::InvalidCertificateChain);
    }
    for certificate_bytes in intermediate_bytes.iter().rev() {
        let certificate = parse_certificate(certificate_bytes.as_ref())?;
        verify_validity(&certificate, now)?;
        if !certificate.is_ca() || certificate.verify_signature(Some(issuer.public_key())).is_err()
        {
            return Err(NitroError::InvalidCertificateChain);
        }
        issuer = certificate;
    }
    if leaf.verify_signature(Some(issuer.public_key())).is_err() {
        return Err(NitroError::InvalidCertificateChain);
    }
    Ok(leaf.public_key().subject_public_key.data.to_vec())
}

fn parse_certificate(input: &[u8]) -> Result<X509Certificate<'_>, NitroError> {
    parse_x509_certificate(input)
        .map(|(_, certificate)| certificate)
        .map_err(|_| NitroError::InvalidCertificateChain)
}

fn verify_validity(certificate: &X509Certificate<'_>, now: SystemTime) -> Result<(), NitroError> {
    let now = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| NitroError::TimestampInvalid)?
        .as_secs() as i64;
    if now < certificate.validity().not_before.timestamp()
        || now > certificate.validity().not_after.timestamp()
    {
        return Err(NitroError::InvalidCertificateChain);
    }
    Ok(())
}

fn verify_cert_unix_time(
    certificate: &X509Certificate<'_>,
    now: UnixTime,
) -> Result<(), rustls::Error> {
    let now = now.as_secs() as i64;
    if now < certificate.validity().not_before.timestamp()
        || now > certificate.validity().not_after.timestamp()
    {
        return Err(rustls::Error::General("TLS certificate is not currently valid".into()));
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum NitroError {
    #[error("Nitro PCR policy must explicitly allow at least one value for every PCR")]
    IncompletePolicy,
    #[error("Nitro attestation document exceeds the 16 KiB protocol limit")]
    DocumentTooLarge,
    #[error("malformed COSE_Sign1 attestation document")]
    MalformedCose,
    #[error("COSE_Sign1 is missing its attestation payload")]
    MissingPayload,
    #[error("malformed Nitro attestation payload")]
    MalformedDocument,
    #[error("Nitro COSE signature is invalid")]
    InvalidCoseSignature,
    #[error("Nitro attestation nonce does not match this TLS connection")]
    NonceMismatch,
    #[error("Nitro attestation nonce must have at least 32 bytes")]
    NonceTooShort,
    #[error("Nitro attestation public key does not match the TLS certificate SPKI")]
    SpkiMismatch,
    #[error("Nitro attestation user_data does not bind the protocol, nonce, and SPKI")]
    UserDataMismatch,
    #[error("Nitro attestation module ID does not match policy")]
    ModuleIdMismatch,
    #[error("Nitro attestation timestamp is invalid")]
    TimestampInvalid,
    #[error("Nitro attestation timestamp is in the future")]
    TimestampInFuture,
    #[error("Nitro attestation is stale")]
    Stale,
    #[error("Nitro attestation PCR set differs from the complete policy")]
    PcrSetMismatch,
    #[error("Nitro attestation PCR {0} is not approved")]
    PcrMismatch(usize),
    #[error("Nitro attestation did not include an AWS CA bundle")]
    MissingCaBundle,
    #[error("Nitro attestation does not chain to AWS Nitro Root-G1")]
    UntrustedRoot,
    #[error("Nitro attestation certificate chain is invalid")]
    InvalidCertificateChain,
    #[error("could not generate the Nitro-attested TLS certificate")]
    CertificateGeneration,
    #[error("Nitro attestation generation failed: {0}")]
    AttestationGeneration(String),
}
#[cfg(test)]
mod tests;
