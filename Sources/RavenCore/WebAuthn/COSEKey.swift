import CryptoKit
import Foundation

/// COSE key encoding (06-CONTEXT D-10): the WebAuthn attested-credential
/// public key format. ES256 (-7) is the only algorithm iOS credential
/// providers need in practice, so the encoder emits exactly the RFC 9052 §7
/// EC2 P-256 layout — `{kty: 2, alg: -7, crv: 1, x: 32B, y: 32B}` — with the
/// coordinate byte strings taken from the CryptoKit key's raw representation
/// (`0x04 ‖ x ‖ y`).
public enum COSEKey {

    /// Encodes a P-256 public key as a canonical CBOR EC2 map. The map keys
    /// (1, 3, -1, -2, -3) land in canonical bytewise order through the
    /// `CBOR` encoder's sort, matching what browsers and KeePassXC's own
    /// soft-passkey implementations emit.
    public static func ec2P256(_ publicKey: P256.Signing.PublicKey) -> Data {
        let raw = publicKey.rawRepresentation
        // rawRepresentation is the SEC1 uncompressed point 0x04 ‖ x ‖ y.
        let coordinates = raw.dropFirst()
        let x = coordinates.prefix(32)
        let y = coordinates.suffix(32)
        return CBOR.encode(.map([
            (.int(1), .int(2)),                  // kty: EC2
            (.int(3), .int(-7)),                 // alg: ES256
            (.int(-1), .int(1)),                 // crv: P-256
            (.int(-2), .byteString(Data(x))),    // x coordinate
            (.int(-3), .byteString(Data(y))),    // y coordinate
        ]))
    }
}
