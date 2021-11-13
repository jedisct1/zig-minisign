const clap = @import("clap.zig");
const std = @import("std");
const base64 = std.base64;
const crypto = std.crypto;
const debug = std.debug;
const fs = std.fs;
const fmt = std.fmt;
const heap = std.heap;
const io = std.io;
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
        var it = mem.tokenize(u8, lines_str, "\n");
        const untrusted_comment = it.next() orelse return error.InvalidEncoding;
        var bin1: [74]u8 = undefined;
        try base64.standard.Decoder.decode(&bin1, it.next() orelse return error.InvalidEncoding);
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
        defer allocator.free(sig_str);
        return Signature.decode(allocator, sig_str);
    }
};

const PublicKey = struct {
    untrusted_comment: ?[]u8 = null,
    signature_algorithm: [2]u8 = "Ed".*,
    key_id: [8]u8,
    key: [32]u8,

    fn fromBase64(str: []const u8) !PublicKey {
        if (str.len != 56) {
            return error.InvalidEncoding;
        }
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

    fn decodeFromSsh(pks: []PublicKey, lines: []const u8) ![]PublicKey {
        var lines_it = mem.tokenize(u8, lines, "\n");
        var i: usize = 0;
        while (lines_it.next()) |line| {
            var pk = PublicKey{ .key_id = mem.zeroes([8]u8), .key = undefined };
            const key_type = "ssh-ed25519";

            var it = mem.tokenize(u8, line, " ");
            const header = it.next() orelse return error.InvalidEncoding;
            if (!mem.eql(u8, key_type, header)) {
                return error.InvalidEncoding;
            }
            const encoded_ssh_key = it.next() orelse return error.InvalidEncoding;
            var ssh_key: [4 + key_type.len + 4 + pk.key.len]u8 = undefined;
            try base64.standard.Decoder.decode(&ssh_key, encoded_ssh_key);
            if (mem.readIntBig(u32, ssh_key[0..4]) != key_type.len or
                !mem.eql(u8, ssh_key[4..][0..key_type.len], key_type) or
                mem.readIntBig(u32, ssh_key[4 + key_type.len ..][0..4]) != pk.key.len)
            {
                return error.InvalidEncoding;
            }
            mem.copy(u8, &pk.key, ssh_key[4 + key_type.len + 4 ..]);

            const rest = mem.trim(u8, it.rest(), " \t\r\n");
            const key_id_prefix = "minisign key ";
            if (mem.startsWith(u8, rest, key_id_prefix) and rest.len > key_id_prefix.len) {
                mem.writeIntLittle(u64, &pk.key_id, try fmt.parseInt(u64, rest[key_id_prefix.len..], 16));
            }
            pks[i] = pk;
            i += 1;
            if (i == pks.len) break;
        }
        if (i == 0) {
            return error.InvalidEncoding;
        }
        return pks[0..i];
    }

    fn decode(pks: []PublicKey, lines_str: []const u8) ![]PublicKey {
        if (decodeFromSsh(pks, lines_str)) |pks_| return pks_ else |_| {}

        var it = mem.tokenize(u8, lines_str, "\n");
        _ = it.next() orelse return error.InvalidEncoding;
        const pk = try fromBase64(it.next() orelse return error.InvalidEncoding);
        pks[0] = pk;
        return pks[0..1];
    }

    fn fromFile(allocator: *mem.Allocator, pks: []PublicKey, path: []const u8) ![]PublicKey {
        const fd = try fs.cwd().openFile(path, .{ .read = true });
        defer fd.close();
        const pk_str = try fd.readToEndAlloc(allocator, 4096);
        defer allocator.free(pk_str);
        return PublicKey.decode(pks, pk_str);
    }

    fn verify(self: PublicKey, allocator: *mem.Allocator, fd: fs.File, sig: Signature, prehash: ?bool) !void {
        const null_key_id = mem.zeroes([self.key_id.len]u8);
        if (!mem.eql(u8, &null_key_id, &self.key_id) and !mem.eql(u8, &sig.key_id, &self.key_id)) {
            std.debug.print("Signature was made using a different key\n", .{});
            return error.KeyIdMismatch;
        }
        const signature_algorithm = sig.signature_algorithm;
        const prehashed = if (signature_algorithm[0] == 0x45 and signature_algorithm[1] == 0x64) false else if (signature_algorithm[0] == 0x45 and signature_algorithm[1] == 0x44) true else return error.UnsupportedAlgorithm;
        if (prehash) |want_prehashed| {
            if (prehashed != want_prehashed) {
                return error.SignatureVerificationFailed;
            }
        }
        var digest: [64]u8 = undefined;
        if (prehashed) {
            var h = Blake2b512.init(.{});
            var buf: [mem.page_size]u8 = undefined;
            while (true) {
                const read_nb = try fd.read(&buf);
                if (read_nb == 0) {
                    break;
                }
                h.update(buf[0..read_nb]);
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

fn verify(allocator: *mem.Allocator, pks: []const PublicKey, path: []const u8, sig: Signature, prehash: ?bool) !void {
    for (pks) |pk| {
        const fd = try fs.cwd().openFile(path, .{ .read = true });
        defer fd.close();
        if (pk.verify(allocator, fd, sig, prehash)) |_| {
            return;
        } else |_| {}
    }
    return error.SignatureVerificationFailed;
}

fn convertToSsh(pk: PublicKey) !void {
    const key_type = "ssh-ed25519";
    var ssh_key: [4 + key_type.len + 4 + pk.key.len]u8 = undefined;
    mem.writeIntBig(u32, ssh_key[0..4], key_type.len);
    mem.copy(u8, ssh_key[4..], key_type);
    mem.writeIntBig(u32, ssh_key[4 + key_type.len ..][0..4], pk.key.len);
    mem.copy(u8, ssh_key[4 + key_type.len + 4 ..], &pk.key);

    const Base64Encoder = base64.standard.Encoder;
    var encoded_ssh_key: [Base64Encoder.calcSize(ssh_key.len)]u8 = undefined;
    _ = Base64Encoder.encode(&encoded_ssh_key, &ssh_key);

    const key_id_prefix = "minisign key ";
    var full_ssh_key: [key_type.len + 1 + encoded_ssh_key.len + 1 + key_id_prefix.len + 16 + 1]u8 = undefined;
    _ = try fmt.bufPrint(&full_ssh_key, "{s} {s} {s}{X}\n", .{ key_type, encoded_ssh_key, key_id_prefix, mem.readIntLittle(u64, &pk.key_id) });
    const fd = io.getStdOut();
    _ = try fd.write(&full_ssh_key);
}

const params = params: {
    @setEvalBranchQuota(10000);
    break :params [_]clap.Param(clap.Help){
        clap.parseParam("-h, --help                  Display this help and exit") catch unreachable,
        clap.parseParam("-H, --prehash               Always prehash the input") catch unreachable,
        clap.parseParam("-p, --publickey-path <PATH> Public key path to a file") catch unreachable,
        clap.parseParam("-P, --publickey <STRING>    Public key, as a BASE64-encoded string") catch unreachable,
        clap.parseParam("-m, --input <PATH>          Input file") catch unreachable,
        clap.parseParam("-q, --quiet                 Quiet mode") catch unreachable,
        clap.parseParam("-V, --verify                Verify") catch unreachable,
        clap.parseParam("-C, --convert               Convert the given public key to SSH format") catch unreachable,
    };
};

fn usage() noreturn {
    var out = io.getStdErr().writer();
    out.writeAll("Usage:\n") catch unreachable;
    clap.help(out, &params) catch unreachable;
    os.exit(1);
}

fn doit(gpa_allocator: *mem.Allocator) !void {
    var diag = clap.Diagnostic{};
    var args = clap.parse(clap.Help, &params, .{
        .allocator = gpa_allocator,
        .diagnostic = &diag,
    }) catch |err| {
        diag.report(io.getStdErr().writer(), err) catch {};
        os.exit(1);
    };
    defer args.deinit();

    if (args.flag("--help")) usage();
    const quiet = args.flag("--quiet");
    const prehash: ?bool = if (args.flag("--prehash")) true else null;
    const pk_b64 = args.option("--publickey");
    const pk_path = args.option("--publickey-path");
    const input_path = args.option("--input");

    if (pk_path == null and pk_b64 == null) {
        usage();
    }
    var pks_buf: [64]PublicKey = undefined;
    const pks = if (pk_b64) |b64| blk: {
        pks_buf[0] = try PublicKey.fromBase64(b64);
        break :blk pks_buf[0..1];
    } else try PublicKey.fromFile(gpa_allocator, &pks_buf, pk_path.?);

    if (args.flag("--convert")) {
        return convertToSsh(pks[0]);
    }

    if (input_path == null) {
        usage();
    }
    var arena = heap.ArenaAllocator.init(gpa_allocator);
    defer arena.deinit();
    const sig_path = try fmt.allocPrint(&arena.allocator, "{s}.minisig", .{input_path});
    const sig = try Signature.fromFile(&arena.allocator, sig_path);
    if (verify(&arena.allocator, pks, input_path.?, sig, prehash)) {
        if (!quiet) {
            debug.print("Signature and comment signature verified\nTrusted comment: {s}\n", .{sig.trusted_comment});
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
