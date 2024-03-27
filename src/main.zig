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
const Endian = std.builtin.Endian;

const lib = @import("lib.zig");
const PublicKey = lib.PublicKey;
const Signature = lib.Signature;

fn verify(allocator: mem.Allocator, pks: []const PublicKey, path: []const u8, sig: Signature, prehash: ?bool) !void {
    var i: usize = pks.len;
    while (i > 0) {
        i -= 1;
        const fd = try fs.cwd().openFile(path, .{ .mode = .read_only });
        defer fd.close();
        if (pks[i].verifyFile(allocator, fd, sig, prehash)) |_| {
            return;
        } else |_| {}
    }
    return error.SignatureVerificationFailed;
}

fn convertToSsh(pk: PublicKey) !void {
    const key_type = "ssh-ed25519";
    const pk_len = pk.key.len;
    var ssh_key: [4 + key_type.len + 4 + pk_len]u8 = undefined;
    mem.writeInt(u32, ssh_key[0..4], key_type.len, Endian.big);
    mem.copyForwards(u8, ssh_key[4..], key_type);
    mem.writeInt(u32, ssh_key[4 + key_type.len ..][0..4], pk.key.len, Endian.big);
    mem.copyForwards(u8, ssh_key[4 + key_type.len + 4 ..], &pk.key);

    const Base64Encoder = base64.standard.Encoder;
    var encoded_ssh_key: [Base64Encoder.calcSize(ssh_key.len)]u8 = undefined;
    _ = Base64Encoder.encode(&encoded_ssh_key, &ssh_key);

    const key_id_prefix = "minisign key ";
    var full_ssh_key: [key_type.len + 1 + encoded_ssh_key.len + 1 + key_id_prefix.len + 16 + 1]u8 = undefined;
    _ = try fmt.bufPrint(&full_ssh_key, "{s} {s} {s}{X}\n", .{ key_type, encoded_ssh_key, key_id_prefix, mem.readInt(u64, &pk.key_id, Endian.little) });
    const fd = io.getStdOut();
    _ = try fd.write(&full_ssh_key);
}

const params = clap.parseParamsComptime(
    \\ -h, --help                  Display this help and exit
    \\ -p, --publickey-path <PATH> Public key path to a file
    \\ -P, --publickey <STRING>    Public key, as a BASE64-encoded string
    \\ -l, --legacy                Accept legacy signatures
    \\ -m, --input <PATH>          Input file
    \\ -q, --quiet                 Quiet mode
    \\ -V, --verify                Verify
    \\ -C, --convert               Convert the given public key to SSH format
);

fn usage() noreturn {
    var out = io.getStdErr().writer();
    out.writeAll("Usage:\n") catch unreachable;
    clap.help(out, clap.Help, &params, .{}) catch unreachable;
    os.exit(1);
}

fn doit(gpa_allocator: mem.Allocator) !void {
    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, .{
        .PATH = clap.parsers.string,
        .STRING = clap.parsers.string,
    }, .{
        .allocator = gpa_allocator,
        .diagnostic = &diag,
    }) catch |err| {
        diag.report(io.getStdErr().writer(), err) catch {};
        os.exit(1);
    };
    defer res.deinit();

    if (res.args.help != 0) usage();
    const quiet = res.args.quiet;
    const prehash: ?bool = if (res.args.legacy != 0) null else true;
    const pk_b64 = res.args.publickey;
    const pk_path = @field(res.args, "publickey-path");
    const input_path = res.args.input;

    if (pk_path == null and pk_b64 == null) {
        usage();
    }
    var pks_buf: [64]PublicKey = undefined;
    const pks = if (pk_b64) |b64| blk: {
        pks_buf[0] = try PublicKey.fromBase64(b64);
        break :blk pks_buf[0..1];
    } else try PublicKey.fromFile(gpa_allocator, &pks_buf, pk_path.?);

    if (res.args.convert != 0) {
        return convertToSsh(pks[0]);
    }

    if (input_path == null) {
        usage();
    }
    var arena = heap.ArenaAllocator.init(gpa_allocator);
    defer arena.deinit();
    const sig_path = try fmt.allocPrint(arena.allocator(), "{s}.minisig", .{input_path.?});
    const sig = try Signature.fromFile(arena.allocator(), sig_path);
    if (verify(arena.allocator(), pks, input_path.?, sig, prehash)) {
        if (quiet == 0) {
            debug.print("Signature and comment signature verified\nTrusted comment: {s}\n", .{sig.trusted_comment});
        }
    } else |_| {
        if (quiet == 0) {
            debug.print("Signature verification failed\n", .{});
        }
        os.exit(1);
    }
}

pub fn main() !void {
    var gpa = heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    try doit(gpa.allocator());
}
