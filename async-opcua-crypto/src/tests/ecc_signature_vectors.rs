//! Cross-stack ECDSA signature conformance (OPC UA Part 6 §6.8).
//!
//! These are independent known-answer vectors generated with OpenSSL 3.0 — an EC key, a fixed
//! message, and an ECDSA signature over it (curve-canonical hash: SHA-256 for P-256, SHA-384 for
//! P-384), captured in BOTH the DER `Ecdsa-Sig-Value` form (used by X.509/CRL verification) and the
//! IEEE P1363 raw `r || s` form (the OPC UA wire form, Part 6 §6.8). Verifying an *independent*
//! signer's output in both encodings exercises async-opcua's P1363↔DER handling — the area of the
//! previously-found "Length-field signature" bug — against a real reference (cf. the OPC Foundation
//! `OPCUA-ECC-CodeFragments` ecdsa-conversion reference).
//!
//! Generation (per curve), message = "OPC UA ECC cross-stack signature vector":
//!   openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:<P-256|secp384r1>
//!   openssl dgst -sha256|-sha384 -sign key -out sig.der msg   ; DER -> r||s left-padded to scalar len

use crate::ecc::{ecdsa_verify, ecdsa_verify_der, EccCurve, EccPublicKey};

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

const MSG: &str = "4f5043205541204543432063726f73732d737461636b207369676e617475726520766563746f72";

struct Vector {
    curve: EccCurve,
    pub_sec1: &'static str, // uncompressed SEC1 (0x04 || X || Y)
    der: &'static str,
    p1363: &'static str,
}

const VECTORS: &[Vector] = &[
    Vector {
        curve: EccCurve::P256,
        pub_sec1: "04aee5a7681b6016dad343f4f197bc61c6823f1bba1e841621c9c24b153728962667f15cffe862710e73e52dc9b0c6498901648f9a65600b59b62381401ef33fd3",
        der: "304502207ddb46e671a4e2462f36c2bd909b1ef80f9d136f400c0ca13d7bbd2ac5557110022100c311235700abb249cb2f316cd66d2ddc6d2181e10d282651472ff67f53e4fb02",
        p1363: "7ddb46e671a4e2462f36c2bd909b1ef80f9d136f400c0ca13d7bbd2ac5557110c311235700abb249cb2f316cd66d2ddc6d2181e10d282651472ff67f53e4fb02",
    },
    Vector {
        curve: EccCurve::P384,
        pub_sec1: "04e3de2573ec17d9202463b5d093e514126d8d5985ad019e87699a9bcabe87e1de31b96231a7a2ab8cd400c3ff687c8c43c9ab1cd8b3f98b3771a9215ab74a0b2fd43a2c9adec7b8f63e26b164c8bc6891c672c8a6436513443a9525e43b3c0cd3",
        der: "3064023024c1a3b83557a4284d07e8bbea36aa0bc574af8aa2fb0582acb9ab710b97c990daa91173484033b8bfbcc8b78e8080b0023014f8502632b4d0177c16472feabce133ade0985eefec2abd94ada7acfbdfd295cf27463bc4ba5e6752f9fd751b8cfb58",
        p1363: "24c1a3b83557a4284d07e8bbea36aa0bc574af8aa2fb0582acb9ab710b97c990daa91173484033b8bfbcc8b78e8080b014f8502632b4d0177c16472feabce133ade0985eefec2abd94ada7acfbdfd295cf27463bc4ba5e6752f9fd751b8cfb58",
    },
];

#[test]
fn opcf_ecdsa_signature_vectors() {
    let msg = unhex(MSG);
    for v in VECTORS {
        let key = EccPublicKey::from_sec1_bytes(v.curve, &unhex(v.pub_sec1))
            .unwrap_or_else(|e| panic!("{:?}: bad public key: {e}", v.curve));
        let p1363 = unhex(v.p1363);
        let der = unhex(v.der);

        // The P1363 raw r||s form is the OPC UA Part 6 §6.8 wire form.
        ecdsa_verify(&key, &msg, &p1363).unwrap_or_else(|e| {
            panic!(
                "{:?}: P1363 verify of an OpenSSL signature failed: {e}",
                v.curve
            )
        });
        // The DER form is what X.509 / CRL verification consumes.
        ecdsa_verify_der(&key, &msg, &der).unwrap_or_else(|e| {
            panic!(
                "{:?}: DER verify of an OpenSSL signature failed: {e}",
                v.curve
            )
        });

        // A flipped bit in the signature must fail (both forms).
        let mut bad = p1363.clone();
        bad[0] ^= 0x01;
        assert!(
            ecdsa_verify(&key, &msg, &bad).is_err(),
            "{:?}: tampered P1363 signature must not verify",
            v.curve
        );
        // A different message must fail.
        assert!(
            ecdsa_verify(&key, b"not the signed message", &p1363).is_err(),
            "{:?}: signature must not verify against a different message",
            v.curve
        );
        // A truncated/wrong-length raw signature must be rejected, not panic.
        assert!(
            ecdsa_verify(&key, &msg, &p1363[..p1363.len() - 1]).is_err(),
            "{:?}: wrong-length raw signature must be rejected",
            v.curve
        );
    }
}
