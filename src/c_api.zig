const impl = @import("verify_api");
const lib = @import("minizign");
const PublicKey = lib.PublicKey;
const Signature = lib.Signature;
const Verifier = lib.Verifier;

export fn minizign_public_key_size() usize {
    return @sizeOf(PublicKey);
}

fn unwrapPtrResult(result: impl.Result, error_out: ?*i32) ?*anyopaque {
    if (@as(isize, @intFromEnum(result)) > 0) {
        if (error_out) |p| {
            p.* = 0;
        }
        return @ptrFromInt(@as(usize, @intCast(@intFromEnum(result))));
    }

    if (error_out) |p| {
        p.* = @intCast(@intFromEnum(result));
    }
    return null;
}

/// Takes a minisign signature and creates a Signature object in memory.
/// On success, returns a pointer. On failure, returns 0 and sets error_out
export fn minizign_signature_create(
    str: [*]const u8,
    len: u32,
    error_out: ?*i32
    ) ?*anyopaque {
    return unwrapPtrResult(impl.signatureDecode(str, len), error_out);
}

export fn minizign_signature_destroy(sig: *anyopaque) void {
  impl.signatureDeinit(@ptrCast(@alignCast(sig)));
}

/// Takes base64 input and creates a Public Key object in memory.
/// On success, returns a pointer. On failure, returns 0 and sets error_out
///
/// You should free results with `minizign_public_key_destroy()`
export fn minizign_public_key_create_from_base64(
    str: [*]const u8,
    len: u32,
    error_out: ?*i32
) ?*anyopaque {
    return unwrapPtrResult(impl.publicKeyDecodeFromBase64(str, len), error_out);
}

/// Create Public key objects in place.
/// PublicKey should be allocated based on `minizign_public_key_size()`
/// On success, returns number of keys
/// On failure, returns a negative error code
export fn minizign_public_key_decode_from_ssh(
    pks: [*]PublicKey,
    pksLength: usize,
    lines: [*]const u8,
    linesLength: usize,
) isize {
    return @intFromEnum(impl.publicKeyDecodeFromSsh(pks, pksLength, lines, linesLength));
}

export fn minizign_public_key_destroy(pk: *PublicKey) void {
  impl.publicKeyDeinit(pk);
}

export fn minizign_verifier_create(
    pk: *const PublicKey,
    sig: *const Signature,
    error_out: ?*i32) ?*anyopaque {
    return unwrapPtrResult(impl.publicKeyVerifier(pk, sig), error_out);
}

export fn minizign_verifier_update(
    verifier: *Verifier,
    bytes: [*]const u8,
    length: u32) void {
    impl.verifierUpdate(verifier, bytes, length);
}

/// Finalizes the hash over bytes previously passed to the verifier through
/// calls to verifierUpdate and returns a Result value.
///
/// If negative, an error has occurred and the file should not be trusted.
/// If the signature is valid, the result should be the value 1.
export fn minizign_verifier_verify(verifier: *Verifier) isize {
    return @intFromEnum(impl.verifierVerify(verifier));
}

/// De-initialize a verifier struct from a call to minizign_verifier_create
export fn minizign_verifier_destroy(verifier: *Verifier) void {
    impl.verifierDeinit(verifier);
}
