const impl = @import("verify_lib");

pub const Result = impl.Result;

/// Allocate a buffer in wasm memory
export fn allocate(len: u32) Result {
    return impl.allocate(len);
}

/// Free a buffer in wasm memory
export fn free(pointer: [*]u8, len: u32) void {
    alloc.free(pointer[0..len]);
}

/// Takes minisign signature and creates a Signature object in memory.
/// On success, returns the number of bytes used. On failure, returns 0.
export fn signatureDecode(str: [*]const u8, len: u32) Result {
    return impl.signatureDecode(str, len);
}

/// Returns the pointer to the signatures trusted comment.
export fn signatureGetTrustedComment(sig: *const Signature) [*]const u8 {
    return impl.signatureGetTrustedComment(sig);
}

/// Returns the length of the signatures trusted comment.
export fn signatureGetTrustedCommentLength(sig: *const Signature) usize {
    return impl.signatureGetTrustedCommentLength(sig);
}

/// De-initializes a signature object from a call to signatureDecode.
export fn signatureDeinit(sig: *Signature) void {
    return impl.signatureDeinit();
}

/// Takes a base64 encoded string and creates a PublicKey object in the provided buffer.
/// On success, returns the number of bytes used. On failure, returns 0.
export fn publicKeyDecodeFromBase64(str: [*]const u8, len: u32) Result {
    return impl.publicKeyDecodeFromBase64(str, len);
}

/// Initialize a list of public keys from an ssh encoded file.
/// Returns the number of keys decoded or an error code.
export fn publicKeyDecodeFromSsh(
    pks: [*]PublicKey,
    pksLength: usize,
    lines: [*]const u8,
    linesLength: usize,
) Result {
    return impl.publicKeyDecodeFromSsh(pks, pksLength, lines, linesLength);
}

/// De-initialize a public key object from a call to any publicKeyDecode* function.
export fn publicKeyDeinit(pk: *PublicKey) void {
    return impl.publicKeyDeinit(pk);
}

/// Creates an incremental Verifier struct from the given public key.
/// Returns a pointer to the struct or an error code.
export fn publicKeyVerifier(pk: *const PublicKey, sig: *const Signature) Result {
    return impl.publicKeyVerifier(pk, sig);
}

/// Add bytes to by verified.
export fn verifierUpdate(verifier: *Verifier, bytes: [*]const u8, length: u32) void {
    return impl.verifierUpdate(verifier, bytes, length);
}

/// Finalizes the hash over bytes previously passed to the verifier through
/// calls to verifierUpdate and returns a Result value. If negative, an error
/// has occurred and the file should not be trusted. Otherwise, the result
/// should be the value 1.
export fn verifierVerify(verifier: *Verifier) Result {
    return impl.verifierVerify(verifier);
}

/// De-initialize a verifier struct from a call to publicKeyVerifier
export fn verifierDeinit(verifier: *Verifier) void {
    return impl.verifierDeinit(verifier);
}
