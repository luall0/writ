// WritSESpike: Plan A of docs/architecture/macos-secure-enclave.md. A Secure Enclave key kept
// in the data protection keychain under a keychain access group, which only apps signed with
// that group's entitlement (Personal Team provisioning profile) can use.
//
// Run the bundle's executable from a terminal:
//   WritSESpike.app/Contents/MacOS/WritSESpike info
//   … create | sign | delete | watch <log> [secs]
//   … sign --group <TEAMID.dev.writ.daemon>   (for a binary without the entitlement)
import Foundation
import Security

let tag = Data("dev.writ.spike.agent".utf8)

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("WritSESpike: \(message)\n".utf8))
    exit(1)
}

func describe(_ status: OSStatus) -> String {
    let text = SecCopyErrorMessageString(status, nil).map { $0 as String } ?? "?"
    return "OSStatus \(status) (\(text))"
}

/// The access groups this binary is entitled to, from its own code signature.
func entitledGroups() -> [String] {
    guard let task = SecTaskCreateFromSelf(nil),
          let value = SecTaskCopyValueForEntitlement(task, "keychain-access-groups" as CFString, nil)
    else { return [] }
    return (value as? [String]) ?? []
}

var args = Array(CommandLine.arguments.dropFirst())
var groupOverride: String?
if let i = args.firstIndex(of: "--group"), i + 1 < args.count {
    groupOverride = args[i + 1]
    args.removeSubrange(i...(i + 1))
}
let group = groupOverride ?? entitledGroups().first { $0.hasSuffix(".dev.writ.daemon") }

func baseQuery() -> [String: Any] {
    var query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tag,
        kSecUseDataProtectionKeychain as String: true,
    ]
    if let group { query[kSecAttrAccessGroup as String] = group }
    return query
}

func create() {
    guard let group else { fail("no keychain access group (entitlement missing?)") }
    var error: Unmanaged<CFError>?
    guard let control = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, &error)
    else { fail("access control: \(error!.takeRetainedValue())") }
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecAttrAccessGroup as String: group,
        kSecUseDataProtectionKeychain as String: true,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag,
            kSecAttrAccessControl as String: control,
        ] as [String: Any],
    ]
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        fail("create: \(error!.takeRetainedValue())")
    }
    let publicKey = SecKeyCopyPublicKey(key).flatMap { SecKeyCopyExternalRepresentation($0, nil) }
    print("created in group \(group)")
    print("public key (x963): \((publicKey as Data?)?.base64EncodedString() ?? "?")")
}

/// Finds the key, signs and verifies; returns a one-line result.
func signOnce() -> String {
    var query = baseQuery()
    query[kSecReturnRef as String] = true
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess, let item else { return "error: lookup \(describe(status))" }
    let key = item as! SecKey
    let message = Data("writ spike \(Date())".utf8)
    let start = Date()
    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(
        key, .ecdsaSignatureMessageX962SHA256, message as CFData, &error)
    else { return "error: sign \(error!.takeRetainedValue())" }
    let ms = Int(Date().timeIntervalSince(start) * 1000)
    guard let publicKey = SecKeyCopyPublicKey(key),
          SecKeyVerifySignature(publicKey, .ecdsaSignatureMessageX962SHA256, message as CFData, signature, nil)
    else { return "error: signature does not verify" }
    return "ok \(ms)ms"
}

switch args.first {
case "info":
    print("uid \(getuid()), entitled groups: \(entitledGroups()), using: \(group ?? "none")")
case "create":
    create()
case "sign":
    let result = signOnce()
    print(result)
    exit(result.hasPrefix("ok") ? 0 : 1)
case "delete":
    let status = SecItemDelete(baseQuery() as CFDictionary)
    print(status == errSecSuccess ? "deleted" : describe(status))
case "watch":
    guard args.count >= 2 else { fail("usage: watch <log> [secs]") }
    let interval = args.count > 2 ? (Double(args[2]) ?? 10) : 10
    let formatter = ISO8601DateFormatter()
    while true {
        let line = "\(formatter.string(from: Date())) uid \(getuid()) \(signOnce())\n"
        if let handle = FileHandle(forWritingAtPath: args[1]) {
            handle.seekToEndOfFile()
            handle.write(Data(line.utf8))
            try? handle.close()
        } else {
            FileManager.default.createFile(atPath: args[1], contents: Data(line.utf8))
        }
        Thread.sleep(forTimeInterval: interval)
    }
default:
    fail("usage: WritSESpike info | create | sign | delete | watch <log> [secs] [--group <group>]")
}
