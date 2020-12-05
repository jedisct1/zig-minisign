const clap = @import("clap.zig");
const std = @import("std");
const base64 = std.base64;
const crypto = std.crypto;
const debug = std.debug;
const fs = std.fs;
const fmt = std.fmt;
const heap = std.heap;
const math = std.math;
const mem = std.mem;
const os = std.os;
const process = std.process;
const Blake2b512 = crypto.hash.blake2.Blake2b512;
const Ed25519 = crypto.sign.Ed25519;

const Signature = struct {
    arena: heap.ArenaAllocator,
    untrusted_comment: []u8,
    signature_algorithm: [2]u8,
    key_id: [8]u8,
    signature: [64]u8,
    trusted_comment: []u8,
    global_signature: [64]u8,

    fn deinit(self: *Signature) void {
        self.arena.deinit();
    }

    fn decode(child_allocator: *mem.Allocator, lines_str: []const u8) !Signature {
        var arena = heap.ArenaAllocator.init(child_allocator);
        errdefer arena.deinit();
        var it = mem.tokenize(lines_str, "\n");
        const untrusted_comment = it.next() orelse return error.InvalidEncoding;
        var bin1: [74]u8 = undefined;
        try base64.standard_decoder.decode(&bin1, it.next() orelse return error.InvalidEncoding);
        var trusted_comment = it.next() orelse return error.InvalidEncoding;
        if (!mem.startsWith(u8, trusted_comment, "trusted comment: ")) {
            return error.InvalidEncoding;
        }
        trusted_comment = trusted_comment["Trusted comment: ".len..];
        var bin2: [64]u8 = undefined;
        try base64.standard_decoder.decode(&bin2, it.next() orelse return error.InvalidEncoding);
        const sig = Signature{
            .arena = arena,
            .untrusted_comment = try mem.dupe(&arena.allocator, u8, untrusted_comment),
            .signature_algorithm = bin1[0..2].*,
            .key_id = bin1[2..10].*,
            .signature = bin1[10..74].*,
            .trusted_comment = try mem.dupe(&arena.allocator, u8, trusted_comment),
            .global_signature = bin2,
        };
        return sig;
    }

    fn fromFile(allocator: *mem.Allocator, path: []const u8) !Signature {
        const fd = try fs.cwd().openFile(path, .{ .read = true });
        defer fd.close();
        const sig_str = try fd.readToEndAlloc(allocator, 4096);
        return Signature.decode(allocator, sig_str);
    }
};

const PublicKey = struct {
    untrusted_comment: ?[]u8 = null,
    signature_algorithm: [2]u8,
    key_id: [8]u8,
    key: [32]u8,

    fn fromBase64(str: []const u8) !PublicKey {
        var bin: [42]u8 = undefined;
        try base64.standard_decoder.decode(&bin, str);
        const signature_algorithm = bin[0..2];
        if (bin[0] != 0x45 or (bin[1] != 0x64 and bin[1] != 0x44)) {
            return error.UnsupportedAlgorithm;
        }
        const pk = PublicKey{
            .signature_algorithm = signature_algorithm.*,
            .key_id = bin[2..10].*,
            .key = bin[10..42].*,
        };
        return pk;
    }

    fn verify(self: PublicKey, allocator: *mem.Allocator, fd: fs.File, sig: Signature) !void {
        const signature_algorithm = sig.signature_algorithm;
        const prehashed = if (signature_algorithm[0] == 0x45 and signature_algorithm[1] == 0x64) false else if (signature_algorithm[0] == 0x45 and signature_algorithm[1] == 0x44) true else return error.UnsupportedAlgorithm;
        var digest: [64]u8 = undefined;
        if (prehashed) {
            var h = Blake2b512.init(.{});
            var buf: [mem.page_size]u8 = undefined;
            while (true) {
                const read_nb = try fd.read(&buf);
                if (read_nb == 0) {
                    break;
                }
                h.update(&buf);
            }
            h.final(&digest);
            try Ed25519.verify(sig.signature, &digest, self.key);
        } else {
            var buf = try fd.readToEndAlloc(allocator, math.maxInt(usize));
            defer allocator.free(buf);
            try Ed25519.verify(sig.signature, buf, self.key);
        }
        var global = try allocator.alloc(u8, sig.signature.len + sig.trusted_comment.len);
        defer allocator.free(global);
        mem.copy(u8, global[0..sig.signature.len], sig.signature[0..]);
        mem.copy(u8, global[sig.signature.len..], sig.trusted_comment);
        try Ed25519.verify(sig.global_signature, global, self.key);
    }
};

fn verify(allocator: *mem.Allocator, pk: PublicKey, path: []const u8, sig: Signature) !void {
    const fd = try fs.cwd().openFile(path, .{ .read = true });
    defer fd.close();
    try pk.verify(allocator, fd, sig);
}

const params = comptime [_]clap.Param(clap.Help){
    clap.parseParam("-h, --help               Display this help and exit.") catch unreachable,
    clap.parseParam("-P, --publickey <STRING> Public key, as a BASE64-encoded string. ") catch unreachable,
    clap.parseParam("-m, --input <FILE>       Input file.") catch unreachable,
    clap.parseParam("-q, --quiet              Quiet mode.") catch unreachable,
    clap.parseParam("-V, --verify             Verify.") catch unreachable,
};

fn usage() noreturn {
    var out = std.io.getStdErr().outStream();
    out.writeAll("Usage:\n") catch unreachable;
    clap.help(out, &params) catch unreachable;
    os.exit(1);
}

fn doit(gpa_allocator: *mem.Allocator) !void {
    var diag: clap.Diagnostic = undefined;
    var args = clap.parse(clap.Help, &params, gpa_allocator, &diag) catch |err| {
        diag.report(std.io.getStdErr().outStream(), err) catch {};
        os.exit(1);
    };
    defer args.deinit();
    var pk_b64: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    const quiet = args.flag("--quiet");
    if (args.option("--publickey")) |arg| {
        pk_b64 = arg;
    }
    if (args.option("--input")) |arg| {
        path = arg;
    }
    if (pk_b64 == null or path == null) {
        usage();
    }
    const pk = try PublicKey.fromBase64(pk_b64.?);

    var arena = heap.ArenaAllocator.init(gpa_allocator);
    defer arena.deinit();
    const path_sig = try fmt.allocPrint(&arena.allocator, "{}.minisig", .{path});
    const sig = try Signature.fromFile(&arena.allocator, path_sig);
    if (verify(&arena.allocator, pk, path.?, sig)) {
        if (!quiet) {
            debug.print("Signature and comment signature verified\nTrusted comment: {}\n", .{sig.trusted_comment});
        }
    } else |_| {
        if (!quiet) {
            debug.print("Signature verification failed\n", .{});
        }
        os.exit(1);
    }
}

pub fn main() !void {
    var gpa = heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    try doit(&gpa.allocator);
}
