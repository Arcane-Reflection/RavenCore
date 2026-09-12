import Foundation

/// ChaCha20 stream cipher — direct translation of RFC 8439/RFC 7539.
/// 20 rounds, 256-bit key, 32-bit block counter, 96-bit nonce.
///
/// This is a thin, vector-verified implementation of a standardized algorithm
/// (not a custom design): Apple system libraries expose ChaCha20 only as the
/// ChaChaPoly AEAD, but KDBX needs the raw stream (outer cipher option and
/// the default inner value-protection stream). Verified against RFC 7539
/// §2.3.2/§2.4.2 vectors in `ChaCha20Tests`.
public struct ChaCha20 {
    private var state: [UInt32] // 16 words
    private var counter: UInt32
    private let nonce: [UInt8] // 12 bytes
    private var keystream: [UInt8] = []
    private var keystreamOffset = 0

    /// - Parameters:
    ///   - key: 32-byte ChaCha20 key.
    ///   - nonce: 12-byte nonce (RFC 7539 layout).
    ///   - initialCounter: starting block counter (0 unless resuming a stream).
    public init(key: Data, nonce: Data, initialCounter: UInt32 = 0) throws {
        guard key.count == 32 else { throw KdbxError.malformedData }
        guard nonce.count == 12 else { throw KdbxError.malformedData }
        state = [
            0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574, // "expand 32-byte k"
            Self.readUInt32LE(key, 0), Self.readUInt32LE(key, 4),
            Self.readUInt32LE(key, 8), Self.readUInt32LE(key, 12),
            Self.readUInt32LE(key, 16), Self.readUInt32LE(key, 20),
            Self.readUInt32LE(key, 24), Self.readUInt32LE(key, 28),
            initialCounter,
            Self.readUInt32LE(nonce, 0), Self.readUInt32LE(nonce, 4),
            Self.readUInt32LE(nonce, 8),
        ]
        counter = initialCounter
        self.nonce = Array(nonce)
    }

    /// Encrypts/decrypts `input` (XOR with keystream), advancing the running
    /// counter. For segment-wise consumption the whole message must be fed in
    /// document order — the cipher state is never reset between segments.
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
        var working = state
        for _ in 0..<10 {
            quarterRound(&working, 0, 4, 8, 12)
            quarterRound(&working, 1, 5, 9, 13)
            quarterRound(&working, 2, 6, 10, 14)
            quarterRound(&working, 3, 7, 11, 15)
            quarterRound(&working, 0, 5, 10, 15)
            quarterRound(&working, 1, 6, 11, 12)
            quarterRound(&working, 2, 7, 8, 13)
            quarterRound(&working, 3, 4, 9, 14)
        }
        keystream = [UInt8](repeating: 0, count: 64)
        keystream.withUnsafeMutableBytes { buf in
            for (i, w) in working.enumerated() {
                let added = w &+ state[i]
                buf.storeBytes(of: added.littleEndian, toByteOffset: i * 4, as: UInt32.self)
            }
        }
        // Advance the 32-bit counter inside the state for the next block.
        counter &+= 1
        state[12] = counter
        keystreamOffset = 0
    }

    private func quarterRound(_ s: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        s[a] &+= s[b]; s[d] ^= s[a]; s[d] = (s[d] << 16) | (s[d] >> 16)
        s[c] &+= s[d]; s[b] ^= s[c]; s[b] = (s[b] << 12) | (s[b] >> 20)
        s[a] &+= s[b]; s[d] ^= s[a]; s[d] = (s[d] << 8) | (s[d] >> 24)
        s[c] &+= s[d]; s[b] ^= s[c]; s[b] = (s[b] << 7) | (s[b] >> 25)
    }

    private static func readUInt32LE(_ data: Data, _ offset: Int) -> UInt32 {
        let start = data.startIndex + offset
        return UInt32(data[start])
            | (UInt32(data[start + 1]) << 8)
            | (UInt32(data[start + 2]) << 16)
            | (UInt32(data[start + 3]) << 24)
    }
}
