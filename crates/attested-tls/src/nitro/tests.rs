use std::{collections::BTreeMap, sync::Mutex, time::Duration};

use aws_nitro_enclaves_nsm_api::api::Digest as NitroDigest;
use coset::{CoseSign1, CoseSign1Builder, TaggedCborSerializable as _};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256,
    PKCS_ECDSA_P384_SHA384,
};
use ring::{
    rand::SystemRandom,
    signature::{
        ECDSA_P384_SHA384_FIXED, ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair,
        KeyPair as RingKeyPair, UnparsedPublicKey,
    },
};
use rustls::{client::danger::ServerCertVerifier as _, pki_types::ServerName};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::*;

struct Fixture {
    certificate: CertificateDer<'static>,
    context: Vec<u8>,
    nonce: Vec<u8>,
    policy: NitroPolicy,
    root_fingerprint: [u8; 32],
    now: SystemTime,
}

struct TestAttester {
    signer: Mutex<EcdsaKeyPair>,
    certificate: Vec<u8>,
    cabundle: Vec<Vec<u8>>,
    pcrs: BTreeMap<usize, Vec<u8>>,
}

impl NitroAttester for TestAttester {
    fn attest(
        &self,
        nonce: &[u8],
        tls_spki: &[u8],
        user_data: &[u8],
    ) -> Result<Vec<u8>, NitroError> {
        let document = AttestationDoc::new(
            "test-nitro-module".into(),
            NitroDigest::SHA256,
            now_millis(SystemTime::now()),
            self.pcrs.clone(),
            self.certificate.clone(),
            self.cabundle.clone(),
            Some(user_data.to_vec()),
            Some(nonce.to_vec()),
            Some(tls_spki.to_vec()),
        );
        let rng = SystemRandom::new();
        let signer = self
            .signer
            .lock()
            .map_err(|_| NitroError::AttestationGeneration("test signer lock poisoned".into()))?;
        CoseSign1Builder::new()
            .payload(document.to_binary())
            .create_signature(&[], |input| signer.sign(&rng, input).unwrap().as_ref().to_vec())
            .build()
            .to_tagged_vec()
            .map_err(|error| NitroError::AttestationGeneration(error.to_string()))
    }
}

fn test_attester() -> (TestAttester, NitroPolicy, [u8; 32]) {
    let rng = SystemRandom::new();
    let root_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
    let root_key = KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(root_pkcs8.as_ref()),
        &PKCS_ECDSA_P384_SHA384,
    )
    .unwrap();
    let mut root_params = CertificateParams::default();
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let root = CertifiedIssuer::self_signed(root_params, root_key).unwrap();

    let signer_pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
    let signer =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, signer_pkcs8.as_ref(), &rng)
            .unwrap();
    let signer_key = KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(signer_pkcs8.as_ref()),
        &PKCS_ECDSA_P384_SHA384,
    )
    .unwrap();
    let signer_params = CertificateParams::new(vec!["nitro-attester.invalid".into()]).unwrap();
    let signer_certificate = signer_params.signed_by(&signer_key, &root).unwrap();
    let pcrs = BTreeMap::from([(0, vec![0x11; 48]), (1, vec![0x22; 48])]);
    let policy = NitroPolicy {
        pcrs: pcrs.iter().map(|(&index, value)| (index, vec![value.clone()])).collect(),
        max_age: Duration::from_secs(60),
        module_id: Some("test-nitro-module".into()),
    };
    (
        TestAttester {
            signer: Mutex::new(signer),
            certificate: signer_certificate.der().to_vec(),
            cabundle: vec![root.der().to_vec()],
            pcrs,
        },
        policy,
        Sha256::digest(root.der().as_ref()).into(),
    )
}

fn now_millis(now: SystemTime) -> u64 {
    now.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() * 1_000
}

fn fixture(document_timestamp: SystemTime, document_spki: Option<Vec<u8>>) -> Fixture {
    let rng = SystemRandom::new();
    let root_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
    let root_key = KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(root_pkcs8.as_ref()),
        &PKCS_ECDSA_P384_SHA384,
    )
    .unwrap();
    let mut root_params = CertificateParams::default();
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let root = CertifiedIssuer::self_signed(root_params, root_key).unwrap();

    let signer_pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
    let signer =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, signer_pkcs8.as_ref(), &rng)
            .unwrap();
    let signer_key = KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(signer_pkcs8.as_ref()),
        &PKCS_ECDSA_P384_SHA384,
    )
    .unwrap();
    let signer_params = CertificateParams::new(vec!["nitro-attester.invalid".into()]).unwrap();
    let signer_certificate = signer_params.signed_by(&signer_key, &root).unwrap();
    let parsed_signer = parse_certificate(signer_certificate.der().as_ref()).unwrap();
    assert_eq!(parsed_signer.public_key().subject_public_key.data, signer.public_key().as_ref());

    let tls_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let tls_spki = tls_key.subject_public_key_info();
    let context = b"example-attested-transport/1".to_vec();
    let nonce = vec![7_u8; 32];
    let pcrs = BTreeMap::from([(0, vec![0x11; 48]), (1, vec![0x22; 48])]);
    let bound_spki = document_spki.unwrap_or_else(|| tls_spki.clone());
    let document = AttestationDoc::new(
        "test-nitro-module".into(),
        NitroDigest::SHA256,
        now_millis(document_timestamp),
        pcrs.clone(),
        signer_certificate.der().to_vec(),
        vec![root.der().to_vec()],
        Some(
            binding_user_data(NitroBinding {
                context: &context,
                nonce: &nonce,
                tls_spki: &bound_spki,
            })
            .to_vec(),
        ),
        Some(nonce.clone()),
        Some(bound_spki),
    );
    let evidence = CoseSign1Builder::new()
        .payload(document.to_binary())
        .create_signature(&[], |input| signer.sign(&rng, input).unwrap().as_ref().to_vec())
        .build()
        .to_tagged_vec()
        .unwrap();
    let cose = CoseSign1::from_tagged_slice(&evidence).unwrap();
    cose.verify_signature(&[], |signature, data| {
        UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, signer.public_key())
            .verify(data, signature)
            .map_err(|_| ())
    })
    .unwrap();

    let mut tls_params = CertificateParams::new(vec!["tempo-zone-prover.invalid".into()]).unwrap();
    tls_params
        .custom_extensions
        .push(CustomExtension::from_oid_content(NITRO_ATTESTATION_OID, evidence));
    let certificate =
        CertificateDer::from(tls_params.self_signed(&tls_key).unwrap().der().to_vec());
    Fixture {
        certificate,
        context,
        nonce,
        policy: NitroPolicy {
            pcrs: pcrs.into_iter().map(|(index, value)| (index, vec![value])).collect(),
            max_age: Duration::from_secs(60),
            module_id: Some("test-nitro-module".into()),
        },
        root_fingerprint: Sha256::digest(root.der().as_ref()).into(),
        now: document_timestamp,
    }
}

fn verifier(fixture: &Fixture) -> NitroServerVerifier {
    NitroServerVerifier {
        policy: fixture.policy.clone(),
        context: fixture.context.clone(),
        nonce: fixture.nonce.clone(),
        provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        trust_anchor_fingerprint: fixture.root_fingerprint,
    }
}

fn verify(
    fixture: &Fixture,
    verifier: NitroServerVerifier,
) -> Result<ServerCertVerified, rustls::Error> {
    verifier.verify_server_cert(
        &fixture.certificate,
        &[],
        &ServerName::try_from("tempo-zone-prover.invalid").unwrap(),
        &[],
        UnixTime::since_unix_epoch(fixture.now.duration_since(SystemTime::UNIX_EPOCH).unwrap()),
    )
}

#[test]
fn authenticates_a_certificate_bound_nitro_document() {
    let fixture = fixture(SystemTime::now(), None);
    let result = verify(&fixture, verifier(&fixture));
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn rejects_invalid_pcr_after_authenticating_the_document() {
    let fixture = fixture(SystemTime::now(), None);
    let mut verifier = verifier(&fixture);
    verifier.policy.pcrs.get_mut(&0).unwrap()[0][0] ^= 0xff;
    assert!(verify(&fixture, verifier).unwrap_err().to_string().contains("PCR 0 is not approved"));
}

#[test]
fn rejects_a_replayed_document_for_a_new_nonce() {
    let fixture = fixture(SystemTime::now(), None);
    let mut verifier = verifier(&fixture);
    verifier.nonce[0] ^= 0xff;
    assert!(verify(&fixture, verifier).unwrap_err().to_string().contains("nonce does not match"));
}

#[test]
fn rejects_a_document_bound_to_a_different_tls_spki() {
    let fixture = fixture(SystemTime::now(), Some(vec![0x42; 91]));
    assert!(
        verify(&fixture, verifier(&fixture))
            .unwrap_err()
            .to_string()
            .contains("public key does not match")
    );
}

#[test]
fn rejects_stale_attestation_evidence() {
    let now = SystemTime::now();
    let fixture = fixture(now.checked_sub(Duration::from_secs(61)).unwrap(), None);
    let verifier = verifier(&fixture);
    let error = verifier.verify_server_cert(
        &fixture.certificate,
        &[],
        &ServerName::try_from("tempo-zone-prover.invalid").unwrap(),
        &[],
        UnixTime::since_unix_epoch(now.duration_since(SystemTime::UNIX_EPOCH).unwrap()),
    );
    assert!(error.unwrap_err().to_string().contains("is stale"));
}

#[tokio::test]
async fn establishes_an_encrypted_tls_stream_after_attestation() {
    let (attester, policy, root_fingerprint) = test_attester();
    let context = b"example-attested-transport/1".to_vec();
    let nonce = vec![9_u8; 32];
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let server_config = server_config_for_nonce(
        &attester,
        &context,
        &nonce,
        "tempo-zone-prover.invalid",
        provider.clone(),
    )
    .unwrap();
    let verifier = NitroServerVerifier {
        policy,
        context,
        nonce,
        provider: provider.clone(),
        trust_anchor_fingerprint: root_fingerprint,
    };
    let client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    let (client_io, server_io) = tokio::io::duplex(32 * 1024);
    let server = tokio::spawn(async move {
        TlsAcceptor::from(Arc::new(server_config)).accept(server_io).await.unwrap()
    });
    let mut client = TlsConnector::from(Arc::new(client_config))
        .connect(ServerName::try_from("tempo-zone-prover.invalid").unwrap().to_owned(), client_io)
        .await
        .unwrap();
    let mut server = server.await.unwrap();
    client.write_all(b"prover-frame").await.unwrap();
    let mut frame = [0_u8; 12];
    server.read_exact(&mut frame).await.unwrap();
    assert_eq!(&frame, b"prover-frame");
}
