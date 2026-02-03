const std = @import("std");
const lib = @import("minizign");
const PublicKey = lib.PublicKey;
const Signature = lib.Signature;
const Io = std.Io;
const Dir = Io.Dir;

/// Verifies data using a public key and a signature (both as strings).
/// Returns 0 on success, or a negative error code.
export fn minisign_verify(
    data: [*]const u8,
    data_size: usize,
    public_key_str: [*:0]const u8,
    signature_str: [*:0]const u8,
) i32 {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var pks_buf: [1]PublicKey = undefined;
    const pks = PublicKey.decode(&pks_buf, std.mem.span(public_key_str)) catch return -1;
    const pk = pks[0];

    var sig = Signature.decode(allocator, std.mem.span(signature_str)) catch return -2;
    defer sig.deinit();

    var v = pk.verifier(&sig) catch return -3;
    v.update(data[0..data_size]);
    v.verify(allocator) catch return -4;

    return 0;
}

/// Verifies a file using a public key file and a signature file.
/// Returns 0 on success, or a negative error code.
export fn minisign_verify_file(
    data_file: [*:0]const u8,
    public_key_file: [*:0]const u8,
    signature_file: [*:0]const u8,
) i32 {
    var threaded = std.Io.Threaded.init_single_threaded;
    const io = threaded.ioBasic();
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var pks_buf: [1]PublicKey = undefined;
    const pks = PublicKey.fromFile(allocator, &pks_buf, std.mem.span(public_key_file), io) catch return -1;
    const pk = pks[0];

    var sig = Signature.fromFile(allocator, std.mem.span(signature_file), io) catch return -2;
    defer sig.deinit();

    const fd = Dir.cwd().openFile(io, std.mem.span(data_file), .{}) catch return -3;
    defer fd.close(io);

    pk.verifyFile(allocator, io, fd, sig, true) catch return -4;

    return 0;
}

fn wideToUtf8(allocator: std.mem.Allocator, wpath: [*:0]const u16) ![:0]u8 {
    return std.unicode.utf16LeToUtf8AllocZ(allocator, std.mem.span(wpath));
}

// For Win32, where UTF-8 code pages are uncommon; support wchar_t
export fn minisign_verify_file_wide(
    data_file_w: [*:0]const u16,
    public_key_file_w: [*:0]const u16,
    signature_file_w: [*:0]const u16,
) i32 {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const data_path = wideToUtf8(allocator, data_file_w) catch return -1;
    defer allocator.free(data_path);

    const pk_path = wideToUtf8(allocator, public_key_file_w) catch return -1;
    defer allocator.free(pk_path);

    const sig_path = wideToUtf8(allocator, signature_file_w) catch return -1;
    defer allocator.free(sig_path);

    return minisign_verify_file(data_path, pk_path, sig_path);
}
