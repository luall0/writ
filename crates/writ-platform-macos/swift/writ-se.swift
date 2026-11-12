// writ-se: the Secure Enclave helper of writd (docs/architecture/signer.md#a-helper-process).
//
// Speaks writ-se/1 on stdin and stdout, one request at a time, and keeps no state: each
// request carries the key's blob (CryptoKit's dataRepresentation, usable only by this Mac's
// Secure Enclave). P-256 only. Keys are made with the access control `privateKeyUsage` alone
// and `AfterFirstUnlockThisDeviceOnly`: no prompt, the screen locked or not.
//
// Frames: a 4-byte big-endian length, then the body. A request: an operation byte (1 hello,
// 2 create, 3 public, 4 sign), then its fields, each a 4-byte length and its bytes. An
// answer: 0 and its fields, or 1 and one code of [a-z0-9-]. No `try!` and no force unwrap:
// every error is answered by its code. writd checks every answer; a crash inside CryptoKit
// (a corrupted blob) costs writd one job.

import CryptoKit
import Darwin
import Foundation
import Security

let protocolName = "writ-se/1"
// What writd sends at most: 16 MiB of data and room for the blob and the framing.
let maxRequest = 16 * 1024 * 1024 + 64 * 1024

enum Op: UInt8 {
    case hello = 1
    case create = 2
    case publicPoint = 3
    case sign = 4
}

struct Refusal: Error {
    let code: String
}

func readExact(_ count: Int) -> [UInt8]? {
    var buffer = [UInt8](repeating: 0, count: count)
    var done = 0
    while done < count {
        let n = buffer.withUnsafeMutableBytes { raw -> Int in
            guard let base = raw.baseAddress else { return -1 }
            return read(0, base + done, count - done)
        }
        if n <= 0 { return nil }
        done += n
    }
    return buffer
}

func writeAll(_ bytes: [UInt8]) -> Bool {
    var done = 0
    while done < bytes.count {
        let n = bytes.withUnsafeBytes { raw -> Int in
            guard let base = raw.baseAddress else { return -1 }
            return write(1, base + done, bytes.count - done)
        }
        if n <= 0 { return false }
        done += n
    }
    return true
}

func be32(_ value: Int) -> [UInt8] {
    let v = UInt32(truncatingIfNeeded: value)
    return [UInt8(v >> 24 & 0xff), UInt8(v >> 16 & 0xff), UInt8(v >> 8 & 0xff), UInt8(v & 0xff)]
}

func readBe32(_ bytes: ArraySlice<UInt8>) -> Int {
    bytes.reduce(0) { ($0 << 8) | Int($1) }
}

func fields(_ body: ArraySlice<UInt8>) throws -> [Data] {
    var out: [Data] = []
    var rest = body
    while !rest.isEmpty {
        guard rest.count >= 4 else { throw Refusal(code: "bad-request") }
        let len = readBe32(rest.prefix(4))
        rest = rest.dropFirst(4)
        guard rest.count >= len else { throw Refusal(code: "bad-request") }
        out.append(Data(rest.prefix(len)))
        rest = rest.dropFirst(len)
    }
    return out
}

func ok(_ answer: [Data]) -> [UInt8] {
    var out: [UInt8] = [0]
    for field in answer {
        out += be32(field.count)
        out += [UInt8](field)
    }
    return out
}

func refused(_ code: String) -> [UInt8] {
    let bytes = [UInt8](code.utf8)
    return [1] + be32(bytes.count) + bytes
}

func key(_ blob: Data) throws -> SecureEnclave.P256.Signing.PrivateKey {
    do {
        return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
    } catch {
        throw Refusal(code: "invalid-blob")
    }
}

func handle(_ op: Op, _ args: [Data]) throws -> [Data] {
    switch op {
    case .hello:
        guard args.isEmpty else { throw Refusal(code: "bad-request") }
        guard SecureEnclave.isAvailable else { throw Refusal(code: "no-secure-enclave") }
        return [Data(protocolName.utf8)]
    case .create:
        guard args.count == 1 else { throw Refusal(code: "bad-request") }
        guard args[0] == Data("p256".utf8) else { throw Refusal(code: "unsupported-algorithm") }
        guard SecureEnclave.isAvailable else { throw Refusal(code: "no-secure-enclave") }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, &error)
        else { throw Refusal(code: "access-control-failed") }
        do {
            let made = try SecureEnclave.P256.Signing.PrivateKey(
                compactRepresentable: false, accessControl: access)
            return [made.dataRepresentation, made.publicKey.x963Representation]
        } catch {
            throw Refusal(code: "create-failed")
        }
    case .publicPoint:
        guard args.count == 1 else { throw Refusal(code: "bad-request") }
        return [try key(args[0]).publicKey.x963Representation]
    case .sign:
        guard args.count == 2 else { throw Refusal(code: "bad-request") }
        let signer = try key(args[0])
        do {
            return [try signer.signature(for: args[1]).rawRepresentation]
        } catch {
            throw Refusal(code: "sign-failed")
        }
    }
}

while true {
    guard let header = readExact(4) else { exit(0) }
    let len = readBe32(header[...])
    guard len >= 1, len <= maxRequest, let body = readExact(len) else { exit(1) }
    let answer: [UInt8]
    if let op = Op(rawValue: body[0]) {
        do {
            answer = ok(try handle(op, try fields(body.dropFirst())))
        } catch let refusal as Refusal {
            answer = refused(refusal.code)
        } catch {
            answer = refused("failed")
        }
    } else {
        answer = refused("bad-request")
    }
    guard writeAll(be32(answer.count) + answer) else { exit(1) }
}
