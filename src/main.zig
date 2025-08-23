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
const process = std.process;
const Blake2b512 = crypto.hash.blake2.Blake2b512;
const Ed25519 = crypto.sign.Ed25519;
const Endian = std.builtin.Endian;

const lib = @import("minizign");
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
    var buf: [1024]u8 = undefined;
    var stderr_writer = std.fs.File.stderr().writer(&buf);
    const stderr = &stderr_writer.interface;
    stderr.writeAll("Usage:\n") catch unreachable;
    clap.help(stderr, clap.Help, &params, .{}) catch unreachable;
    stderr.flush() catch unreachable;
    process.exit(1);
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
        var buf: [1024]u8 = undefined;
        var stderr_writer = std.fs.File.stderr().writer(&buf);
        const stderr = &stderr_writer.interface;
        diag.report(stderr, err) catch {};
        stderr.flush() catch {};
        process.exit(1);
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
        pks_buf[0] = try PublicKey.decodeFromBase64(b64);
        break :blk pks_buf[0..1];
    } else try PublicKey.fromFile(gpa_allocator, &pks_buf, pk_path.?);

    if (res.args.convert != 0) {
        const ssh_key = pks[0].getSshKey();
        const fd = std.fs.File.stdout();
        _ = try fd.write(&ssh_key);
        return;
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
        process.exit(1);
    }
}

pub fn main() !void {
    var gpa = heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    try doit(gpa.allocator());
}
