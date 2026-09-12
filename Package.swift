// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "RavenCore",
    platforms: [
        .iOS(.v16),
        .macOS(.v13)
    ],
    products: [
        .library(name: "RavenCore", targets: ["RavenCore"])
    ],
    targets: [
        // Vendored Argon2 reference C (pin: Sources/CArgon2/UPSTREAM.md).
        // ref.c only — opt.c/thread.c deliberately excluded (arm64 + hermeticity).
        .target(
            name: "CArgon2",
            path: "Sources/CArgon2",
            exclude: ["UPSTREAM.md", "LICENSE"],
            sources: [
                "src/argon2.c",
                "src/core.c",
                "src/encoding.c",
                "src/ref.c",
                "src/thread.c",
                "src/blake2/blake2b.c",
            ],
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("src"),
                .headerSearchPath("src/blake2"),
            ]
        ),
        // Vendored BIP39 English wordlist (pin: Seed/Bip39.swift doc comment).
        // .copy keeps the resource byte-verbatim — the load-time validator
        // requires exactly 2048 LF lines and would tripwire on any rewrite.
        .target(
            name: "RavenCore",
            dependencies: ["CArgon2"],
            resources: [
                .copy("Seed/Resources/bip39-english.txt")
            ]
        ),
        .testTarget(name: "RavenCoreTests", dependencies: ["RavenCore"])
    ]
)
