// swift-tools-version:6.0
// M0 spike: CryptoKit Secure Enclave keys without any entitlement (Plans B and C of
// docs/architecture/macos-secure-enclave.md). Not part of the Cargo workspace.
import PackageDescription

let package = Package(
    name: "se-cryptokit",
    platforms: [.macOS(.v14)],
    targets: [.executableTarget(name: "se-cryptokit")]
)
