// se-cryptokit: create a Secure Enclave P-256 key with CryptoKit, keep only its encrypted blob
// (`dataRepresentation`), and sign with it. Used to answer the ⚠️ points of Plans B and C.
//
//   se-cryptokit create <blob>              new key, blob written 0600, public key printed
//   se-cryptokit sign <blob> [message]      sign once, verify, print the result and timing
//   se-cryptokit watch <blob> <log> [secs]  sign every <secs> (default 10), one log line each
//   se-cryptokit daemon <dir> [secs]        Plan B LaunchDaemon: create <dir>/key.blob if
//                                           missing, then sign every <secs>, logging to stdout
import CryptoKit
import Foundation
import Security
import SystemConfiguration

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("se-cryptokit: \(message)\n".utf8))
    exit(1)
}

func whoami() -> String {
    let uid = getuid()
    let name = getpwuid(uid).map { String(cString: $0.pointee.pw_name) } ?? "?"
    return "\(name) (uid \(uid))"
}

func accessControl() -> SecAccessControl {
    var error: Unmanaged<CFError>?
    // .privateKeyUsage only: no Touch ID, no password, usable while the screen is locked
    // once the device was unlocked after boot.
    guard let control = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, &error)
    else { fail("access control: \(error!.takeRetainedValue())") }
    return control
}

func load(_ path: String) throws -> SecureEnclave.P256.Signing.PrivateKey {
    let blob = try Data(contentsOf: URL(fileURLWithPath: path))
    return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
}

/// Signs and verifies; returns a one-line result.
func signOnce(_ path: String, _ message: Data) -> String {
    let start = Date()
    do {
        let key = try load(path)
        let signature = try key.signature(for: message)
        let valid = key.publicKey.isValidSignature(signature, for: message)
        let ms = Int(Date().timeIntervalSince(start) * 1000)
        return valid ? "ok \(ms)ms" : "error: signature does not verify"
    } catch {
        return "error: \(error)"
    }
}

/// Who is logged in at the console ("none" at the login window, before anyone logs in).
func consoleUser() -> String {
    guard let name = SCDynamicStoreCopyConsoleUser(nil, nil, nil) as String?,
          name != "loginwindow" else { return "none" }
    return name
}

func create(at url: URL) throws -> SecureEnclave.P256.Signing.PrivateKey {
    let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl())
    try key.dataRepresentation.write(to: url, options: .withoutOverwriting)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    return key
}

let args = CommandLine.arguments
switch args.dropFirst().first {
case "create":
    guard args.count == 3 else { fail("usage: create <blob>") }
    guard SecureEnclave.isAvailable else { fail("no Secure Enclave on this Mac") }
    do {
        let url = URL(fileURLWithPath: args[2])
        let key = try create(at: url)
        print("created by \(whoami())")
        print("blob: \(url.path) (\(key.dataRepresentation.count) bytes)")
        print("public key (x963): \(key.publicKey.x963Representation.base64EncodedString())")
    } catch {
        fail("create: \(error)")
    }
case "sign":
    guard args.count >= 3 else { fail("usage: sign <blob> [message]") }
    let message = Data((args.count > 3 ? args[3] : "writ spike \(Date())").utf8)
    let result = signOnce(args[2], message)
    print("\(whoami()): \(result)")
    exit(result.hasPrefix("ok") ? 0 : 1)
case "watch":
    guard args.count >= 4 else { fail("usage: watch <blob> <log> [secs]") }
    let interval = args.count > 4 ? (Double(args[4]) ?? 10) : 10
    let formatter = ISO8601DateFormatter()
    while true {
        let now = Date()
        let line = "\(formatter.string(from: now)) \(whoami()) \(signOnce(args[2], Data("watch \(now)".utf8)))\n"
        if let handle = FileHandle(forWritingAtPath: args[3]) {
            handle.seekToEndOfFile()
            handle.write(Data(line.utf8))
            try? handle.close()
        } else {
            FileManager.default.createFile(atPath: args[3], contents: Data(line.utf8))
        }
        Thread.sleep(forTimeInterval: interval)
    }
case "daemon":
    guard args.count >= 3 else { fail("usage: daemon <dir> [secs]") }
    setvbuf(stdout, nil, _IOLBF, 0)
    let interval = args.count > 3 ? (Double(args[3]) ?? 10) : 10
    let formatter = ISO8601DateFormatter()
    let blob = URL(fileURLWithPath: args[2]).appendingPathComponent("key.blob")
    print("\(formatter.string(from: Date())) start as \(whoami()), console user \(consoleUser())")
    if !FileManager.default.fileExists(atPath: blob.path) {
        do {
            let key = try create(at: blob)
            print("\(formatter.string(from: Date())) created \(blob.path), public key (x963) "
                + key.publicKey.x963Representation.base64EncodedString())
        } catch {
            // Keep running: the next lines show whether it ever works (e.g. after a login).
            print("\(formatter.string(from: Date())) create failed: \(error)")
        }
    }
    while true {
        let result = FileManager.default.fileExists(atPath: blob.path)
            ? signOnce(blob.path, Data("daemon \(Date())".utf8))
            : "no key yet"
        print("\(formatter.string(from: Date())) console \(consoleUser()) \(result)")
        Thread.sleep(forTimeInterval: interval)
    }
default:
    fail("usage: se-cryptokit create <blob> | sign <blob> [message] | watch <blob> <log> [secs] | daemon <dir> [secs]")
}
