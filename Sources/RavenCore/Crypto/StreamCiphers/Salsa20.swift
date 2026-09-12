import CryptoKit
import Foundation

/// Salsa20 stream cipher (eSTREAM specification, 20 rounds, 256-bit key,
/// 64-bit nonce + 64-bit block counter).
///
/// Needed for KDBX 3.1 read support: 3.1's value-protection stream is Salsa20
/// with key = SHA-256(K) and the fixed nonce E8 30 09 4B 97 20 5D 2A.
/// Vector-verified in `Salsa20Tests` (eSTREAM/SETUP vectors).
public struct Salsa20 {
    private var state: [UInt32] // 16 words
    private var blockCounter: UInt64 = 0
    private var keystream: [UInt8] = []
    private var keystreamOffset = 0

    /// - Parameters:
    ///   - key: 32-byte Salsa20 key.
    ///   - nonce: 8-byte nonce (KDBX inner stream layout).
    public init(key: Data, nonce: Data) throws {
        guard key.count == 32 else { throw KdbxError.malformedData }
        guard nonce.count == 8 else { throw KdbxError.malformedData }
        let sigma: [UInt32] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574] // "expand 32-byte k"
        state = [
            sigma[0],
            Self.readUInt32LE(key, 0), Self.readUInt32LE(key, 4), Self.readUInt32LE(key, 8), Self.readUInt32LE(key, 12),
            sigma[1],
            Self.readUInt32LE(nonce, 0), Self.readUInt32LE(nonce, 4),
            0, 0, // block counter
            sigma[2],
            Self.readUInt32LE(key, 16), Self.readUInt32LE(key, 20), Self.readUInt32LE(key, 24), Self.readUInt32LE(key, 28),
            sigma[3],
        ]
    }

    /// XORs `input` with the keystream, advancing stream state across calls
    /// (segmented consumption must equal one-shot — T-02-05).
    public mutating func apply(_ input: Data) -> Data {
        var output = Data(count: input.count)
        output.withUnsafeMutableBytes { outBuf in
            input.withUnsafeBytes { inBuf in
                let inBytes = inBuf.bindMemory(to: UInt8.self)
                let outBytes = outBuf.bindMemory(to: UInt8.self)
                for i in 0 ..< input.count {
                    if keystreamOffset >= keystream.count {
                        refill()
                    }
                    outBytes[i] = inBytes[i] ^ keystream[keystreamOffset]
                    keystreamOffset += 1
                }
            }
        }
        return output
    }

    private mutating func refill() {
        var x = state
        for _ in 0..<10 {
            columnRound(&x)
            rowRound(&x)
        }
        keystream = [UInt8](repeating: 0, count: 64)
        keystream.withUnsafeMutableBytes { buf in
            for (i, w) in x.enumerated() {
                buf.storeBytes(of: w &+ state[i], toByteOffset: i * 4, as: UInt32.self)
            }
        }
        blockCounter &+= 1
        state[8] = UInt32(truncatingIfNeeded: blockCounter)
        state[9] = UInt32(truncatingIfNeeded: blockCounter >> 32)
        keystreamOffset = 0
    }

    private func quarterRound(_ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: inout [UInt32]) {
        x[b] ^= rotateLeft(x[a] &+ x[d], 7)
        x[c] ^= rotateLeft(x[b] &+ x[a], 9)
        x[d] ^= rotateLeft(x[c] &+ x[b], 13)
        x[a] ^= rotateLeft(x[d] &+ x[c], 18)
    }

    private func columnRound(_ x: inout [UInt32]) {
        quarterRound(0, 4, 8, 12, &x)
        quarterRound(5, 9, 13, 1, &x)
        quarterRound(10, 14, 2, 6, &x)
        quarterRound(15, 3, 7, 11, &x)
    }

    private func rowRound(_ x: inout [UInt32]) {
        quarterRound(0, 1, 2, 3, &x)
        quarterRound(5, 6, 7, 4, &x)
        quarterRound(10, 11, 8, 9, &x)
        quarterRound(15, 12, 13, 14, &x)
    }

    private func rotateLeft(_ v: UInt32, _ bits: UInt32) -> UInt32 {
        (v << bits) | (v >> (32 - bits))
    }

    private static func readUInt32LE(_ data: Data, _ offset: Int) -> UInt32 {
        let start = data.startIndex + offset
        return UInt32(data[start])
            | (UInt32(data[start + 1]) << 8)
            | (UInt32(data[start + 2]) << 16)
            | (UInt32(data[start + 3]) << 24)
    }
}
