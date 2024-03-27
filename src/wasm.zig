const std = @import("std");
const lib = @import("minizign");
const PublicKey = lib.PublicKey;
const Signature = lib.Signature;
const Verifier = lib.Verifier;

const alloc = std.heap.wasm_allocator;

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
    _,

    // Assert that none of the error code values are positive.
    comptime {
        const type_info = @typeInfo(Result);
        for (type_info.Enum.fields) |field| {
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
