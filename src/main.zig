const clap = @import("clap.zig");
const std = @import("std");
const base64 = std.base64;
const crypto = std.crypto;
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
const SecretKey = lib.SecretKey;

fn verify(allocator: mem.Allocator, pks: []const PublicKey, path: []const u8, sig: Signature, prehash: ?bool) !void {
    var had_key_id_mismatch = false;
    var i: usize = pks.len;
    while (i > 0) {
        i -= 1;
        const fd = try fs.cwd().openFile(path, .{ .mode = .read_only });
        defer fd.close();
        if (pks[i].verifyFile(allocator, fd, sig, prehash)) |_| {
            return;
        } else |err| {
            if (err == error.KeyIdMismatch) {
                had_key_id_mismatch = true;
            }
        }
    }
    return if (had_key_id_mismatch) error.KeyIdMismatch else error.SignatureVerificationFailed;
}

fn sign(allocator: mem.Allocator, sk_path: []const u8, input_path: []const u8, sig_path: []const u8, trusted_comment: []const u8, untrusted_comment: []const u8, io: std.Io) !void {
    // Load secret key
    var sk = try SecretKey.fromFile(allocator, sk_path, io);
    defer sk.deinit();

    // Get password if key is encrypted
    if (mem.eql(u8, &sk.kdf_algorithm, "Sc")) {
        const password = try getPassword(allocator, io);
        defer allocator.free(password);
        try sk.decrypt(allocator, password);
    }

    // Open input file
    const fd = try fs.cwd().openFile(input_path, .{ .mode = .read_only });
    defer fd.close();

    // Sign the file (prehash mode by default)
    var signature = try sk.signFile(allocator, fd, true, trusted_comment);
    defer signature.deinit();

    // Write signature to file
    try signature.toFile(sig_path, untrusted_comment);
}

fn generate(allocator: mem.Allocator, sk_path: []const u8, pk_path: []const u8, password: ?[]const u8) !void {
    // Generate new keypair
    var sk = try SecretKey.generate(allocator);
    defer sk.deinit();

    // Extract public key BEFORE encryption
    const pk = sk.getPublicKey();

    // Encrypt if password is provided
    if (password) |pwd| {
        try sk.encrypt(allocator, pwd);
    }

    // Save secret key and public key
    try sk.toFile(sk_path);
    try pk.toFile(pk_path);
}

fn getPassword(allocator: mem.Allocator, io: std.Io) ![]u8 {
    const stderr = fs.File.stderr();
    const builtin = @import("builtin");
    const has_termios = builtin.os.tag != .wasi;

    // On Unix, try to open /dev/tty for secure password reading
    // This prevents buffered input from being echoed if the process is killed
    var tty_file: ?fs.File = null;
    var input_file: fs.File = undefined;

    if (has_termios) {
        // Try to open /dev/tty first (more secure)
        tty_file = fs.openFileAbsolute("/dev/tty", .{ .mode = .read_write }) catch null;
        input_file = tty_file orelse fs.File.stdin();
    } else {
        input_file = fs.File.stdin();
    }
    defer if (tty_file) |f| f.close();

    const is_terminal = if (has_termios) std.posix.isatty(input_file.handle) else false;

    var original: std.posix.termios = undefined;
    if (has_termios and is_terminal) {
        original = try std.posix.tcgetattr(input_file.handle);
        var raw = original;

        // Set raw mode to prevent any buffering
        // Disable canonical mode (line buffering)
        raw.lflag.ICANON = false;
        // Disable all echo
        raw.lflag.ECHO = false;
        raw.lflag.ECHONL = false;
        // Disable signal generation
        raw.lflag.ISIG = false;
        // Disable extended input processing
        raw.lflag.IEXTEN = false;

        // Disable input processing flags
        raw.iflag.BRKINT = false;
        raw.iflag.ICRNL = false;
        raw.iflag.INPCK = false;
        raw.iflag.ISTRIP = false;
        raw.iflag.IXON = false;

        // Set minimum characters to read and timeout
        raw.cc[@intFromEnum(std.posix.V.MIN)] = 1; // Read at least 1 character
        raw.cc[@intFromEnum(std.posix.V.TIME)] = 0; // No timeout

        try std.posix.tcsetattr(input_file.handle, .FLUSH, raw);
        try stderr.writeAll("Password: ");
    }
    defer if (has_termios and is_terminal) {
        stderr.writeAll("\n") catch {};
        std.posix.tcsetattr(input_file.handle, .FLUSH, original) catch {};
    };

    // Read password character by character in raw mode
    var password = std.ArrayList(u8){};
    defer password.deinit(allocator);

    if (has_termios and is_terminal) {
        // Raw mode: read character by character
        var buf: [1]u8 = undefined;
        while (true) {
            const n = try input_file.read(&buf);
            if (n == 0) break; // EOF

            const c = buf[0];
            if (c == '\n' or c == '\r') {
                break;
            } else if (c == 127 or c == 8) { // Backspace or Delete
                if (password.items.len > 0) {
                    _ = password.pop();
                }
            } else if (c == 3) { // Ctrl+C
                return error.Interrupted;
            } else if (c >= 32) { // Printable ASCII (32-126) and all UTF-8 multibyte bytes (>= 128)
                try password.append(allocator, c);
            }
        }
    } else {
        // Non-terminal: read line normally
        var reader_buf: [1024]u8 = undefined;
        var reader = input_file.reader(io, &reader_buf);
        const line = try reader.interface.takeDelimiterExclusive('\n');
        try password.appendSlice(allocator, line);
    }

    return password.toOwnedSlice(allocator);
}

const params = clap.parseParamsComptime(
    \\ -h, --help                       Display this help and exit
    \\ -p, --publickey-path <PATH>      Public key path to a file
    \\ -P, --publickey <STRING>         Public key, as a BASE64-encoded string
    \\ -s, --secretkey-path <PATH>      Secret key path to a file
    \\ -l, --legacy                     Accept legacy signatures
    \\ -m, --input <PATH>               Input file
    \\ -o, --output <PATH>              Output file (signature)
    \\ -q, --quiet                      Quiet mode
    \\ -V, --verify                     Verify
    \\ -S, --sign                       Sign
    \\ -G, --generate                   Generate a new key pair
    \\ -C, --convert                    Convert the given public key to SSH format
    \\ -t, --trusted-comment <STRING>   Trusted comment
    \\ -c, --untrusted-comment <STRING> Untrusted comment
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

fn getDefaultSecretKeyPath(allocator: mem.Allocator) !?[]u8 {
    const builtin = @import("builtin");

    // First check MINISIGN_CONFIG_DIR environment variable
    if (process.getEnvVarOwned(allocator, "MINISIGN_CONFIG_DIR")) |config_dir| {
        defer allocator.free(config_dir);
        const path = try fmt.allocPrint(allocator, "{s}{c}minisign.key", .{ config_dir, fs.path.sep });
        return path;
    } else |_| {}

    // Try $HOME/.minisign/minisign.key
    if (process.getEnvVarOwned(allocator, "HOME")) |home| {
        defer allocator.free(home);
        const path = try fmt.allocPrint(allocator, "{s}{c}.minisign{c}minisign.key", .{ home, fs.path.sep, fs.path.sep });
        // Check if file exists, if not continue to next option
        fs.cwd().access(path, .{}) catch {
            allocator.free(path);
            // File doesn't exist, try app data dir (not available on WASI)
            if (builtin.os.tag != .wasi) {
                if (fs.getAppDataDir(allocator, "minisign")) |app_dir| {
                    defer allocator.free(app_dir);
                    const app_path = try fmt.allocPrint(allocator, "{s}{c}minisign.key", .{ app_dir, fs.path.sep });
                    return app_path;
                } else |_| {}
            }
            return null;
        };
        return path;
    } else |_| {}

    // Try app data directory (not available on WASI)
    if (builtin.os.tag != .wasi) {
        if (fs.getAppDataDir(allocator, "minisign")) |app_dir| {
            defer allocator.free(app_dir);
            const path = try fmt.allocPrint(allocator, "{s}{c}minisign.key", .{ app_dir, fs.path.sep });
            return path;
        } else |_| {}
    }

    // No default available
    return null;
}

fn doit(gpa_allocator: mem.Allocator) !void {
    var threaded = std.Io.Threaded.init_single_threaded;
    const io = threaded.ioBasic();

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
    const sk_path_arg = @field(res.args, "secretkey-path");
    const input_path = res.args.input;
    const output_path = res.args.output;
    const sign_mode = res.args.sign != 0;
    const generate_mode = res.args.generate != 0;

    // Determine secret key path (from arg or default)
    const default_sk_path = try getDefaultSecretKeyPath(gpa_allocator);
    defer if (default_sk_path) |path| gpa_allocator.free(path);
    const sk_path = sk_path_arg orelse default_sk_path;

    // Handle key generation mode
    if (generate_mode) {
        if (sk_path == null) {
            var stderr_writer = fs.File.stderr().writer(&.{});
            stderr_writer.interface.writeAll("Error: Secret key path (-s) is required for key generation\n") catch {};
            usage();
        }

        var arena = heap.ArenaAllocator.init(gpa_allocator);
        defer arena.deinit();

        const public_key_path = if (pk_path) |path| path else blk: {
            break :blk try fmt.allocPrint(arena.allocator(), "{s}.pub", .{sk_path.?});
        };

        const sk_exists = if (fs.cwd().access(sk_path.?, .{})) true else |_| false;
        const pk_exists = if (fs.cwd().access(public_key_path, .{})) true else |_| false;

        if (sk_exists or pk_exists) {
            const stderr = fs.File.stderr();
            const stdin = fs.File.stdin();
            var stderr_writer = stderr.writer(&.{});
            const writer = &stderr_writer.interface;

            if (sk_exists and pk_exists) {
                try writer.writeAll("Warning: Both key files already exist:\n");
                try writer.print("  {s}\n", .{sk_path.?});
                try writer.print("  {s}\n", .{public_key_path});
            } else if (sk_exists) {
                try writer.print("Warning: Secret key file already exists: {s}\n", .{sk_path.?});
            } else {
                try writer.print("Warning: Public key file already exists: {s}\n", .{public_key_path});
            }

            try stderr.writeAll("Overwrite? (y/N): ");

            var response_buf: [10]u8 = undefined;
            var reader = stdin.reader(io, &response_buf);
            const response = reader.interface.takeDelimiterExclusive('\n') catch "";

            const trimmed = mem.trim(u8, response, &std.ascii.whitespace);
            if (!mem.eql(u8, trimmed, "y") and !mem.eql(u8, trimmed, "Y")) {
                try writer.writeAll("Aborted.\n");
                process.exit(1);
            }

            // Delete existing files if user confirmed
            if (sk_exists) {
                try fs.cwd().deleteFile(sk_path.?);
            }
            if (pk_exists) {
                try fs.cwd().deleteFile(public_key_path);
            }
        }

        // Prompt for password
        const stderr = fs.File.stderr();
        try stderr.writeAll("Enter password (leave empty for unencrypted key): ");
        const password = try getPassword(arena.allocator(), io);
        defer arena.allocator().free(password);

        const pwd = if (password.len > 0) password else null;

        try generate(arena.allocator(), sk_path.?, public_key_path, pwd);

        if (quiet == 0) {
            var stdout_writer = fs.File.stdout().writer(&.{});
            const writer = &stdout_writer.interface;
            try writer.print("Secret key written to {s}\n", .{sk_path.?});
            try writer.print("Public key written to {s}\n", .{public_key_path});
        }
        return;
    }

    // Handle signing mode
    if (sign_mode) {
        if (input_path == null) usage();
        if (sk_path == null) {
            var stderr_writer = fs.File.stderr().writer(&.{});
            stderr_writer.interface.writeAll("Error: Secret key path is required for signing\n") catch {};
            usage();
        }

        var arena = heap.ArenaAllocator.init(gpa_allocator);
        defer arena.deinit();

        const sig_path = if (output_path) |path| path else blk: {
            break :blk try fmt.allocPrint(arena.allocator(), "{s}.minisig", .{input_path.?});
        };

        const trusted_comment = if (@field(res.args, "trusted-comment")) |tc| tc else blk: {
            const now = try std.Io.Clock.Timestamp.now(io, .real);
            const timestamp = now.raw.toSeconds();
            break :blk try fmt.allocPrint(arena.allocator(), "timestamp:{d}", .{timestamp});
        };

        const untrusted_comment = if (@field(res.args, "untrusted-comment")) |uc| uc else "signature from minizign secret key";

        try sign(arena.allocator(), sk_path.?, input_path.?, sig_path, trusted_comment, untrusted_comment, io);

        if (quiet == 0) {
            var stdout_writer = fs.File.stdout().writer(&.{});
            try stdout_writer.interface.print("Signature written to {s}\n", .{sig_path});
        }
        return;
    }

    // Handle conversion mode
    if (pk_path == null and pk_b64 == null) {
        usage();
    }
    var pks_buf: [64]PublicKey = undefined;
    const pks = if (pk_b64) |b64| blk: {
        pks_buf[0] = try PublicKey.decodeFromBase64(b64);
        break :blk pks_buf[0..1];
    } else try PublicKey.fromFile(gpa_allocator, &pks_buf, pk_path.?, io);

    if (res.args.convert != 0) {
        const ssh_key = pks[0].getSshKey();
        const fd = std.fs.File.stdout();
        _ = try fd.write(&ssh_key);
        return;
    }

    // Handle verification mode
    if (input_path == null) {
        usage();
    }
    var arena = heap.ArenaAllocator.init(gpa_allocator);
    defer arena.deinit();
    const sig_path = if (output_path) |path| path else try fmt.allocPrint(arena.allocator(), "{s}.minisig", .{input_path.?});
    const sig = try Signature.fromFile(arena.allocator(), sig_path, io);
    if (verify(arena.allocator(), pks, input_path.?, sig, prehash)) {
        if (quiet == 0) {
            var stdout_writer = fs.File.stdout().writer(&.{});
            try stdout_writer.interface.print("Signature and comment signature verified\nTrusted comment: {s}\n", .{sig.trusted_comment});
        }
    } else |err| {
        if (quiet == 0) {
            var stderr_writer = fs.File.stderr().writer(&.{});
            const writer = &stderr_writer.interface;

            if (err == error.KeyIdMismatch) {
                writer.writeAll("Signature verification failed: key ID mismatch\n") catch {};

                const sig_key_id = mem.readInt(u64, &sig.key_id, Endian.little);
                writer.print("Signature key ID: {X:0>16}\n", .{sig_key_id}) catch {};

                const null_key_id: [8]u8 = @splat(0);
                const prefix = if (pks.len == 1) "Public key ID: " else "Public key IDs:\n  ";
                writer.writeAll(prefix) catch {};

                for (pks, 0..) |pk, i| {
                    if (i > 0) writer.writeAll("\n  ") catch {};
                    if (mem.eql(u8, &pk.key_id, &null_key_id)) {
                        writer.writeAll("(not set)") catch {};
                    } else {
                        const pk_key_id = mem.readInt(u64, &pk.key_id, Endian.little);
                        writer.print("{X:0>16}", .{pk_key_id}) catch {};
                    }
                }
                writer.writeAll("\n") catch {};
            } else {
                writer.writeAll("Signature verification failed\n") catch {};
            }
        }
        process.exit(1);
    }
}

pub fn main() !void {
    var gpa = heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    try doit(gpa.allocator());
}
