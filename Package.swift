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
        // ref.c + thread.c compiled; opt.c (+ blamka-round-opt.h) deliberately
        // excluded — SSE2 breaks arm64 (arm64 + hermeticity, per UPSTREAM.md).
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
        // Vendored wordlists (pins: Seed/Bip39.swift + Generator/PasswordGenerator.swift
        // + HealthIndex/CommonPasswordList.swift doc comments). .copy keeps each
        // resource byte-verbatim — the load-time validators require exact line
        // counts (2048 / 7776 / 10000 LF lines) and would tripwire on any rewrite.
        .target(
            name: "RavenCore",
            dependencies: ["CArgon2"],
            resources: [
                .copy("Seed/Resources/bip39-english.txt"),
                .copy("Generator/Resources/eff-large-wordlist.txt"),
                .copy("HealthIndex/Resources/common-passwords-top10k.txt"),
            ]
        ),
        .testTarget(name: "RavenCoreTests", dependencies: ["RavenCore"])
    ]
)
