const std = @import("std");
const builtin = @import("builtin");
const lib = @import("minizign");
const PublicKey = lib.PublicKey;
const Signature = lib.Signature;
const Verifier = lib.Verifier;

const alloc = if (builtin.target.cpu.arch == .wasm32)
    std.heap.wasm_allocator
else
    std.testing.allocator;

pub const Result = enum(isize) {
    OutOfMemory = -1,
    InvalidEncoding = -2,
    InvalidCharacter = -3,
    InvalidPadding = -4,
    NoSpaceLeft = -5,
    UnsupportedAlgorithm = -6,
    KeyIdMismatch = -7,
    SignatureVerificationFailed = -8,
    NonCanonical = -9,
    IdentityElement = -10,
    WeakPublicKey = -11,
    Overflow = -12,
    UnprintableCharacters = -13,
    _,

    // Assert that none of the error code values are positive.
    comptime {
        const type_info = @typeInfo(Result);
        for (type_info.@"enum".fields) |field| {
            if (field.value >= 0) {
                @compileError("Result values must be negative.");
            }
        }
    }

    /// Given a pointer, convert it first to an integer, and then to the
    /// Result enum type. Asserts the highest bit is *not* set.
    fn fromPointer(ptr: *anyopaque) Result {
        const int: usize = @intFromPtr(ptr);

        // Assert that the first bit is not set since that would
        // make it a negative value.
        std.debug.assert(@clz(int) >= 1);

        return @enumFromInt(int);
    }
};

/// Allocate a buffer in wasm memory
export fn allocate(len: u32) Result {
    const buf = alloc.alloc(u8, len) catch |e| switch (e) {
        error.OutOfMemory => return .OutOfMemory,
    };
    return Result.fromPointer(buf.ptr);
}

/// Free a buffer in wasm memory
export fn free(pointer: [*]u8, len: u32) void {
    alloc.free(pointer[0..len]);
}

/// Takes minisign signature and creates a Signature object in memory.
/// On success, returns the number of bytes used. On failure, returns 0.
export fn signatureDecode(str: [*]const u8, len: u32) Result {
    const sig = struct {
        fn impl(str_: [*]const u8, len_: u32) !*Signature {
            const sig: *Signature = try alloc.create(Signature);
            errdefer alloc.destroy(sig);

            sig.* = try Signature.decode(alloc, str_[0..len_]);

            return sig;
        }
    }.impl(str, len) catch |e| switch (e) {
        error.OutOfMemory => return .OutOfMemory,
        error.InvalidEncoding => return .InvalidEncoding,
        error.InvalidCharacter => return .InvalidCharacter,
        error.InvalidPadding => return .InvalidPadding,
        error.NoSpaceLeft => return .NoSpaceLeft,
        error.UnprintableCharacters => return .UnprintableCharacters,
    };
    return Result.fromPointer(sig);
}

/// Returns the pointer to the signatures trusted comment.
export fn signatureGetTrustedComment(sig: *const Signature) [*]const u8 {
    return sig.trusted_comment.ptr;
}

/// Returns the length of the signatures trusted comment.
export fn signatureGetTrustedCommentLength(sig: *const Signature) usize {
    return sig.trusted_comment.len;
}

/// De-initializes a signature object from a call to signatureDecode.
export fn signatureDeinit(sig: *Signature) void {
    sig.deinit();
    alloc.destroy(sig);
}

/// Takes a base64 encoded string and creates a PublicKey object in the provided buffer.
/// On success, returns the number of bytes used. On failure, returns 0.
export fn publicKeyDecodeFromBase64(str: [*]const u8, len: u32) Result {
    const pk = struct {
        fn impl(str_: [*]const u8, len_: u32) !*PublicKey {
            const pk: *PublicKey = try alloc.create(PublicKey);
            errdefer alloc.destroy(pk);

            pk.* = try PublicKey.decodeFromBase64(str_[0..len_]);

            return pk;
        }
    }.impl(str, len) catch |e| switch (e) {
        error.OutOfMemory => return .OutOfMemory,
        error.InvalidEncoding => return .InvalidEncoding,
        error.InvalidCharacter => return .InvalidCharacter,
        error.InvalidPadding => return .InvalidPadding,
        error.NoSpaceLeft => return .NoSpaceLeft,
        error.UnsupportedAlgorithm => return .UnsupportedAlgorithm,
    };

    return Result.fromPointer(pk);
}

/// Initialize a list of public keys from an ssh encoded file.
/// Returns the number of keys decoded or an error code.
export fn publicKeyDecodeFromSsh(
    pks: [*]PublicKey,
    pksLength: usize,
    lines: [*]const u8,
    linesLength: usize,
) Result {
    const result = PublicKey.decodeFromSsh(pks[0..pksLength], lines[0..linesLength]) catch |e| switch (e) {
        error.InvalidEncoding => return .InvalidEncoding,
        error.InvalidCharacter => return .InvalidCharacter,
        error.InvalidPadding => return .InvalidPadding,
        error.NoSpaceLeft => return .NoSpaceLeft,
        error.Overflow => return .Overflow,
    };
    return @enumFromInt(result.len);
}

/// De-initialize a public key object from a call to any publicKeyDecode* function.
export fn publicKeyDeinit(pk: *PublicKey) void {
    alloc.destroy(pk);
}

/// Creates an incremental Verifier struct from the given public key.
/// Returns a pointer to the struct or an error code.
export fn publicKeyVerifier(pk: *const PublicKey, sig: *const Signature) Result {
    const verifier = struct {
        fn impl(pk_: *const PublicKey, sig_: *const Signature) !*Verifier {
            const verifier: *Verifier = try alloc.create(Verifier);
            errdefer alloc.destroy(verifier);

            verifier.* = try pk_.verifier(sig_);

            return verifier;
        }
    }.impl(pk, sig) catch |e| switch (e) {
        error.OutOfMemory => return .OutOfMemory,
        error.InvalidEncoding => return .InvalidEncoding,
        error.KeyIdMismatch => return .KeyIdMismatch,
        error.UnsupportedAlgorithm => return .UnsupportedAlgorithm,
        error.NonCanonical => return .NonCanonical,
        error.IdentityElement => return .IdentityElement,
    };

    return Result.fromPointer(verifier);
}

/// Add bytes to by verified.
export fn verifierUpdate(verifier: *Verifier, bytes: [*]const u8, length: u32) void {
    verifier.update(bytes[0..length]);
}

/// Finalizes the hash over bytes previously passed to the verifier through
/// calls to verifierUpdate and returns a Result value. If negative, an error
/// has occurred and the file should not be trusted. Otherwise, the result
/// should be the value 1.
export fn verifierVerify(verifier: *Verifier) Result {
    verifier.verify(alloc) catch |e| switch (e) {
        error.OutOfMemory => return .OutOfMemory,
        error.InvalidEncoding => return .InvalidEncoding,
        error.SignatureVerificationFailed => return .SignatureVerificationFailed,
        error.NonCanonical => return .NonCanonical,
        error.IdentityElement => return .IdentityElement,
        error.WeakPublicKey => return .WeakPublicKey,
    };
    return @enumFromInt(1);
}

/// De-initialize a verifier struct from a call to publicKeyVerifier
export fn verifierDeinit(verifier: *Verifier) void {
    alloc.destroy(verifier);
}

const testing = std.testing;

const test_public_key_base64 = "RWQf2YpvkVxNbvjCrthM42frjc/tf26hSzWpOhbD2NqPNqbxcPSLp1fJ";

const test_signature = "untrusted comment: signature from minizign secret key\n" ++
    "RUQf2YpvkVxNblr+sxVXXUAQnj+/3KcNtjAJcRbfCkh/eovngN0FQa0jVAehA5WqAvw97oHTtjHTwq36LiVAevsz+xmiGcQ9zgw=\n" ++
    "trusted comment: timestamp:1770197043\n" ++
    "dycotv6P141y/NeZ0URhzMhNEceSFxQlnIy1or/NqejcQ2fd6CbcV6iYy6vZrwa5GMXTLzoXVY0PPQTZmAUjDg==";

const test_message = "Hello, World!";

test "Result enum values are negative" {
    try testing.expect(@intFromEnum(Result.OutOfMemory) < 0);
    try testing.expect(@intFromEnum(Result.InvalidEncoding) < 0);
    try testing.expect(@intFromEnum(Result.SignatureVerificationFailed) < 0);
}

test "allocate and free" {
    const result = allocate(100);
    const ptr_int = @intFromEnum(result);
    try testing.expect(ptr_int > 0);

    const ptr: [*]u8 = @ptrFromInt(@as(usize, @intCast(ptr_int)));
    @memset(ptr[0..100], 0xAA);
    free(ptr, 100);
}

test "allocate large buffer" {
    const result = allocate(1024);
    const ptr_int = @intFromEnum(result);
    try testing.expect(ptr_int > 0);

    const ptr: [*]u8 = @ptrFromInt(@as(usize, @intCast(ptr_int)));
    for (0..1024) |i| {
        ptr[i] = @truncate(i);
    }
    free(ptr, 1024);
}

test "signatureDecode valid signature" {
    const result = signatureDecode(test_signature.ptr, test_signature.len);
    const ptr_int = @intFromEnum(result);
    try testing.expect(ptr_int > 0);

    const sig: *Signature = @ptrFromInt(@as(usize, @intCast(ptr_int)));
    const comment = signatureGetTrustedComment(sig);
    const comment_len = signatureGetTrustedCommentLength(sig);
    try testing.expect(comment_len > 0);
    try testing.expect(std.mem.startsWith(u8, comment[0..comment_len], "timestamp:"));
    signatureDeinit(sig);
}

test "signatureDecode invalid signature" {
    const invalid_sig = "not a valid signature";
    const result = signatureDecode(invalid_sig.ptr, invalid_sig.len);
    try testing.expectEqual(Result.InvalidEncoding, result);
}

test "signatureDecode empty input" {
    const empty = "";
    const result = signatureDecode(empty.ptr, empty.len);
    try testing.expectEqual(Result.InvalidEncoding, result);
}

test "publicKeyDecodeFromBase64 valid key" {
    const result = publicKeyDecodeFromBase64(test_public_key_base64.ptr, test_public_key_base64.len);
    const ptr_int = @intFromEnum(result);
    try testing.expect(ptr_int > 0);

    const pk: *PublicKey = @ptrFromInt(@as(usize, @intCast(ptr_int)));
    publicKeyDeinit(pk);
}

test "publicKeyDecodeFromBase64 invalid length" {
    const short_key = "RWQf6LRCGA9i53ml";
    const result = publicKeyDecodeFromBase64(short_key.ptr, short_key.len);
    try testing.expectEqual(Result.InvalidEncoding, result);
}

test "publicKeyDecodeFromBase64 invalid base64" {
    const invalid_key = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
    const result = publicKeyDecodeFromBase64(invalid_key.ptr, 56);
    try testing.expectEqual(Result.InvalidCharacter, result);
}

test "publicKeyDecodeFromSsh valid key" {
    const ssh_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMBaTHaGYzeYmYd5V8hn0gHBJcwQnqk7FgGwpS3bnLmM minisign key 1FE8B442180F62E7\n";
    var pks: [1]PublicKey = undefined;

    const result = publicKeyDecodeFromSsh(&pks, pks.len, ssh_key.ptr, ssh_key.len);
    const count = @intFromEnum(result);
    try testing.expectEqual(@as(isize, 1), count);
    try testing.expect(!std.mem.eql(u8, &pks[0].key_id, &[_]u8{0} ** 8));
}

test "publicKeyDecodeFromSsh invalid format" {
    const invalid_ssh = "not an ssh key";
    var pks: [1]PublicKey = undefined;

    const result = publicKeyDecodeFromSsh(&pks, pks.len, invalid_ssh.ptr, invalid_ssh.len);
    try testing.expectEqual(Result.InvalidEncoding, result);
}

test "full verification workflow with prehash signature" {
    const pk_result = publicKeyDecodeFromBase64(test_public_key_base64.ptr, test_public_key_base64.len);
    const pk_ptr_int = @intFromEnum(pk_result);
    try testing.expect(pk_ptr_int > 0);
    const pk: *PublicKey = @ptrFromInt(@as(usize, @intCast(pk_ptr_int)));
    defer publicKeyDeinit(pk);

    const sig_result = signatureDecode(test_signature.ptr, test_signature.len);
    const sig_ptr_int = @intFromEnum(sig_result);
    try testing.expect(sig_ptr_int > 0);
    const sig: *Signature = @ptrFromInt(@as(usize, @intCast(sig_ptr_int)));
    defer signatureDeinit(sig);

    const verifier_result = publicKeyVerifier(pk, sig);
    const verifier_ptr_int = @intFromEnum(verifier_result);
    try testing.expect(verifier_ptr_int > 0);
    const verifier: *Verifier = @ptrFromInt(@as(usize, @intCast(verifier_ptr_int)));
    defer verifierDeinit(verifier);

    verifierUpdate(verifier, test_message.ptr, test_message.len);

    const verify_result = verifierVerify(verifier);
    try testing.expectEqual(@as(isize, 1), @intFromEnum(verify_result));
}

test "verification fails with wrong message" {
    const pk_result = publicKeyDecodeFromBase64(test_public_key_base64.ptr, test_public_key_base64.len);
    const pk_ptr_int = @intFromEnum(pk_result);
    try testing.expect(pk_ptr_int > 0);
    const pk: *PublicKey = @ptrFromInt(@as(usize, @intCast(pk_ptr_int)));
    defer publicKeyDeinit(pk);

    const sig_result = signatureDecode(test_signature.ptr, test_signature.len);
    const sig_ptr_int = @intFromEnum(sig_result);
    try testing.expect(sig_ptr_int > 0);
    const sig: *Signature = @ptrFromInt(@as(usize, @intCast(sig_ptr_int)));
    defer signatureDeinit(sig);

    const verifier_result = publicKeyVerifier(pk, sig);
    const verifier_ptr_int = @intFromEnum(verifier_result);
    try testing.expect(verifier_ptr_int > 0);
    const verifier: *Verifier = @ptrFromInt(@as(usize, @intCast(verifier_ptr_int)));
    defer verifierDeinit(verifier);

    const wrong_message = "Wrong message!";
    verifierUpdate(verifier, wrong_message.ptr, wrong_message.len);

    const verify_result = verifierVerify(verifier);
    try testing.expectEqual(Result.SignatureVerificationFailed, verify_result);
}

test "verifier with key ID mismatch" {
    const different_pk_base64 = "RWQ/aDkoT504Nren5nFravQC1+BBRKriJSESwsBHC4JRAuQEGqiMnuup";

    const pk_result = publicKeyDecodeFromBase64(different_pk_base64.ptr, different_pk_base64.len);
    const pk_ptr_int = @intFromEnum(pk_result);
    try testing.expect(pk_ptr_int > 0);
    const pk: *PublicKey = @ptrFromInt(@as(usize, @intCast(pk_ptr_int)));
    defer publicKeyDeinit(pk);

    const sig_result = signatureDecode(test_signature.ptr, test_signature.len);
    const sig_ptr_int = @intFromEnum(sig_result);
    try testing.expect(sig_ptr_int > 0);
    const sig: *Signature = @ptrFromInt(@as(usize, @intCast(sig_ptr_int)));
    defer signatureDeinit(sig);

    const verifier_result = publicKeyVerifier(pk, sig);
    try testing.expectEqual(Result.KeyIdMismatch, verifier_result);
}

test "incremental verification" {
    const pk_result = publicKeyDecodeFromBase64(test_public_key_base64.ptr, test_public_key_base64.len);
    const pk_ptr_int = @intFromEnum(pk_result);
    try testing.expect(pk_ptr_int > 0);
    const pk: *PublicKey = @ptrFromInt(@as(usize, @intCast(pk_ptr_int)));
    defer publicKeyDeinit(pk);

    const sig_result = signatureDecode(test_signature.ptr, test_signature.len);
    const sig_ptr_int = @intFromEnum(sig_result);
    try testing.expect(sig_ptr_int > 0);
    const sig: *Signature = @ptrFromInt(@as(usize, @intCast(sig_ptr_int)));
    defer signatureDeinit(sig);

    const verifier_result = publicKeyVerifier(pk, sig);
    const verifier_ptr_int = @intFromEnum(verifier_result);
    try testing.expect(verifier_ptr_int > 0);
    const verifier: *Verifier = @ptrFromInt(@as(usize, @intCast(verifier_ptr_int)));
    defer verifierDeinit(verifier);

    for (test_message) |byte| {
        verifierUpdate(verifier, @as([*]const u8, @ptrCast(&byte)), 1);
    }

    const verify_result = verifierVerify(verifier);
    try testing.expectEqual(@as(isize, 1), @intFromEnum(verify_result));
}
