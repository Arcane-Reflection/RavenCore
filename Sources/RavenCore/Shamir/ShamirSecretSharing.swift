import Foundation

/// Errors thrown by the Shamir module. All `Equatable` for exact-case test
/// assertions; no case carries share material.
public enum ShamirError: Error, Equatable {
    case invalidConfiguration
    case notEnoughShares
    case invalidShares
}

/// A single Shamir share: the evaluation point `index` (1...255) and the
/// per-byte polynomial evaluations. Integrity of share contents is enforced
/// one layer up (GCM-authenticated payloads); Shamir itself only guarantees
/// reconstruction.
public struct ShamirShare: Sendable, Equatable, Codable {
    /// The evaluation point (1...255); never 0 (that would leak the secret).
    public let index: UInt8
    /// Per-byte polynomial evaluations, same length as the secret.
    public let value: Data

    /// Creates a share.
    public init(index: UInt8, value: Data) {
        self.index = index
        self.value = value
    }
}

/// Shamir's Secret Sharing over GF(2^8) with primitive polynomial 0x11D
/// (the standard scheme used by ssss and HashiCorp Vault).
///
/// v1.1 recovery design: the Level 2 recovery secret is split 3-of-5.
/// Any three shares reconstruct it; the vendor participates in no step.
public enum ShamirSecretSharing {

    /// Minimum threshold accepted by `split` (a 1-of-n split is no split).
    public static let minThreshold = 2
    /// Maximum shares GF(2^8) indices allow.
    public static let maxShares = 255

    // MARK: - Public API

    /// Splits `secret` into `totalShares` shares, `threshold` of which are
    /// required to reconstruct. Each secret byte is the constant term of a
    /// fresh random polynomial of degree `threshold - 1`.
    public static func split(secret: Data, threshold: Int, totalShares: Int) throws -> [ShamirShare] {
        guard threshold >= minThreshold,
              totalShares >= threshold,
              totalShares <= maxShares,
              !secret.isEmpty else {
            throw ShamirError.invalidConfiguration
        }

        var shareValues = Array(repeating: Data(), count: totalShares)
        for byte in secret {
            var coefficients = [byte]
            coefficients.reserveCapacity(threshold)
            for _ in 1..<threshold {
                coefficients.append(UInt8.random(in: .min ... .max))
            }
            for i in 0..<totalShares {
                shareValues[i].append(evaluate(coefficients, at: UInt8(i + 1)))
            }
        }
        return (0..<totalShares).map { ShamirShare(index: UInt8($0 + 1), value: shareValues[$0]) }
    }

    /// Reconstructs the secret from at least `threshold` shares with distinct indices.
    public static func combine(shares: [ShamirShare], threshold: Int) throws -> Data {
        guard shares.count >= threshold else { throw ShamirError.notEnoughShares }

        var byIndex = [UInt8: ShamirShare]()
        for share in shares {
            guard share.index >= 1, !share.value.isEmpty else { throw ShamirError.invalidShares }
            if byIndex[share.index] != nil { throw ShamirError.invalidShares }
            byIndex[share.index] = share
        }
        guard byIndex.count >= threshold else { throw ShamirError.notEnoughShares }

        let selected = Array(byIndex.values.prefix(threshold))
        let length = selected[0].value.count
        guard selected.allSatisfy({ $0.value.count == length }) else { throw ShamirError.invalidShares }

        var secret = Data()
        secret.reserveCapacity(length)
        for byteIndex in 0..<length {
            secret.append(lagrangeAtZero(selected, byteIndex: byteIndex))
        }
        return secret
    }

    // MARK: - GF(2^8) arithmetic (irreducible polynomial x^8+x^4+x^3+x^2+1 = 0x11D)

    private static let expTable: [UInt8] = {
        var table = [UInt8](repeating: 0, count: 255)
        var x: UInt8 = 1
        for i in 0..<255 {
            table[i] = x
            x = multiplySlow(x, 2) // 2 (the element x) generates GF(2^8)* for poly 0x11D
        }
        return table
    }()

    private static let logTable: [UInt8] = {
        var table = [UInt8](repeating: 0, count: 256)
        for i in 0..<255 {
            table[Int(expTable[i])] = UInt8(i)
        }
        return table
    }()

    /// Bitwise GF(2^8) multiplication — reference implementation, also used to
    /// bootstrap the log/exp tables.
    static func multiplySlow(_ a: UInt8, _ b: UInt8) -> UInt8 {
        var a = a
        var b = b
        var product: UInt8 = 0
        for _ in 0..<8 {
            if b & 1 != 0 { product ^= a }
            let carry = a & 0x80
            a <<= 1
            if carry != 0 { a ^= 0x1D }
            b >>= 1
        }
        return product
    }

    static func gfMultiply(_ a: UInt8, _ b: UInt8) -> UInt8 {
        guard a != 0, b != 0 else { return 0 }
        let sum = Int(logTable[Int(a)]) + Int(logTable[Int(b)])
        return expTable[sum % 255]
    }

    static func gfDivide(_ a: UInt8, _ b: UInt8) -> UInt8 {
        guard a != 0, b != 0 else { return 0 }
        let diff = Int(logTable[Int(a)]) + 255 - Int(logTable[Int(b)])
        return expTable[diff % 255]
    }

    private static func evaluate(_ coefficients: [UInt8], at x: UInt8) -> UInt8 {
        // Horner's method from the highest-degree coefficient down.
        var result: UInt8 = 0
        for coefficient in coefficients.reversed() {
            result = gfMultiply(result, x) ^ coefficient
        }
        return result
    }

    /// Lagrange basis evaluation at x = 0 for one secret byte.
    /// In GF(2^8) subtraction equals XOR, so (0 - x_m) = x_m.
    private static func lagrangeAtZero(_ shares: [ShamirShare], byteIndex: Int) -> UInt8 {
        var result: UInt8 = 0
        for j in 0..<shares.count {
            let xj = shares[j].index
            let yj = shares[j].value[byteIndex]
            var numerator: UInt8 = 1
            var denominator: UInt8 = 1
            for m in 0..<shares.count where m != j {
                let xm = shares[m].index
                numerator = gfMultiply(numerator, xm)
                denominator = gfMultiply(denominator, xj ^ xm)
            }
            result ^= gfMultiply(yj, gfDivide(numerator, denominator))
        }
        return result
    }
}
