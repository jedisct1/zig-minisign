const clap = @import("clap");
const std = @import("std");
const base64 = std.base64;
const crypto = std.crypto;
const fmt = std.fmt;
const heap = std.heap;
const Io = std.Io;
const math = std.math;
const mem = std.mem;
const process = std.process;
const Dir = Io.Dir;
const File = Io.File;
const Blake2b512 = crypto.hash.blake2.Blake2b512;
const Ed25519 = crypto.sign.Ed25519;
const Endian = std.builtin.Endian;

const lib = @import("minizign");
const PublicKey = lib.PublicKey;
const Signature = lib.Signature;
const SecretKey = lib.SecretKey;

fn verify(allocator: mem.Allocator, io: Io, pks: []const PublicKey, path: []const u8, sig: Signature, prehash: ?bool) !void {
    var had_key_id_mismatch = false;
    var i: usize = pks.len;
    while (i > 0) {
        i -= 1;
        const fd = try Dir.cwd().openFile(io, path, .{});
        defer fd.close(io);
        if (pks[i].verifyFile(allocator, io, fd, sig, prehash)) |_| {
            return;
        } else |err| {
            if (err == error.KeyIdMismatch) {
                had_key_id_mismatch = true;
            }
        }
    }
    return if (had_key_id_mismatch) error.KeyIdMismatch else error.SignatureVerificationFailed;
}

fn generate(allocator: mem.Allocator, io: Io, sk_path: []const u8, pk_path: []const u8, password: ?[]const u8) !void {
    // Generate new keypair
    var sk = try SecretKey.generate(allocator, io);
    defer sk.deinit();

    // Extract public key BEFORE encryption
    const pk = sk.getPublicKey();

    // Encrypt if password is provided
    if (password) |pwd| {
        try sk.encrypt(allocator, io, pwd);
    }

    // Save secret key and public key
    try sk.toFile(io, sk_path);
    try pk.toFile(io, pk_path);
}

fn changePassword(allocator: mem.Allocator, io: Io, sk_path: []const u8) !void {
    var sk = try SecretKey.fromFile(allocator, sk_path, io);
    defer sk.deinit();

    if (mem.eql(u8, &sk.kdf_algorithm, "Sc")) {
        const old_password = try getPasswordWithPrompt(allocator, io, "Current password: ");
        defer allocator.free(old_password);
        try sk.decrypt(allocator, old_password);
    }

    const new_password = try getPasswordWithPrompt(allocator, io, "New password (empty for unencrypted): ");
    defer allocator.free(new_password);

    if (new_password.len > 0) {
        const confirm_password = try getPasswordWithPrompt(allocator, io, "Confirm new password: ");
        defer allocator.free(confirm_password);
        if (!mem.eql(u8, new_password, confirm_password)) {
            return error.PasswordMismatch;
        }
        try sk.encrypt(allocator, io, new_password);
    } else {
        sk.kdf_algorithm = "\x00\x00".*;
    }

    try Dir.cwd().deleteFile(io, sk_path);
    try sk.toFile(io, sk_path);
}

fn getPasswordWithPrompt(allocator: mem.Allocator, io: Io, prompt: []const u8) ![]u8 {
    const stderr = File.stderr();
    const builtin = @import("builtin");
    const native_os = builtin.os.tag;
    const has_termios = native_os != .wasi and native_os != .windows;
    const is_windows = native_os == .windows;

    // On Unix, try to open /dev/tty for secure password reading
    // This prevents buffered input from being echoed if the process is killed
    var tty_file: ?File = null;
    var input_file: File = undefined;

    if (has_termios) {
        // Try to open /dev/tty first (more secure)
        tty_file = Dir.openFileAbsolute(io, "/dev/tty", .{ .mode = .read_write }) catch null;
        input_file = tty_file orelse File.stdin();
    } else {
        input_file = File.stdin();
    }
    defer if (tty_file) |f| f.close(io);

    const is_terminal = if (has_termios)
        (input_file.isTty(io) catch false)
    else if (is_windows)
        (input_file.isTty(io) catch false)
    else
        false;

    // POSIX terminal state
    var original_termios: std.posix.termios = undefined;
    // Windows console state
    var original_console_mode: if (is_windows) std.os.windows.DWORD else void = undefined;

    if (has_termios and is_terminal) {
        original_termios = try std.posix.tcgetattr(input_file.handle);
        var raw = original_termios;

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
        try stderr.writeStreamingAll(io, prompt);
    } else if (is_windows and is_terminal) {
        const windows = std.os.windows;
        const handle = input_file.handle;
        if (windows.kernel32.GetConsoleMode(handle, &original_console_mode) != 0) {
            // Disable echo and line input
            const ENABLE_ECHO_INPUT: windows.DWORD = 0x0004;
            const ENABLE_LINE_INPUT: windows.DWORD = 0x0002;
            const new_mode = original_console_mode & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT);
            _ = windows.kernel32.SetConsoleMode(handle, new_mode);
        }
        try stderr.writeStreamingAll(io, prompt);
    }
    defer if (has_termios and is_terminal) {
        stderr.writeStreamingAll(io, "\n") catch {};
        std.posix.tcsetattr(input_file.handle, .FLUSH, original_termios) catch {};
    };
    defer if (is_windows and is_terminal) {
        stderr.writeStreamingAll(io, "\n") catch {};
        _ = std.os.windows.kernel32.SetConsoleMode(input_file.handle, original_console_mode);
    };

    // Read password character by character in raw mode
    var password = std.ArrayList(u8){};
    defer password.deinit(allocator);

    if ((has_termios or is_windows) and is_terminal) {
        // Raw mode: read character by character
        var buf: [1]u8 = undefined;
        while (true) {
            const n = try input_file.readStreaming(io, &.{&buf});
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
    \\ -m, --input <PATH>...            Input file(s)
    \\ -o, --output <PATH>              Output file (signature)
    \\ -q, --quiet                      Quiet mode
    \\ -V, --verify                     Verify
    \\ -S, --sign                       Sign
    \\ -G, --generate                   Generate a new key pair
    \\ -R, --recreate                   Recreate public key from secret key
    \\ -K, --change-password            Change secret key password
    \\ -C, --convert                    Convert the given public key to SSH format
    \\ -t, --trusted-comment <STRING>   Trusted comment
    \\ -c, --untrusted-comment <STRING> Untrusted comment
);

fn usage(io: Io) noreturn {
    var buf: [1024]u8 = undefined;
    var stderr_writer = File.stderr().writer(io, &buf);
    const stderr = &stderr_writer.interface;
    stderr.writeAll("Usage:\n") catch unreachable;
    clap.help(stderr, clap.Help, &params, .{}) catch unreachable;
    stderr.flush() catch unreachable;
    process.exit(1);
}

fn getAppDataDir(allocator: mem.Allocator, environ: process.Environ, appname: []const u8) !?[]u8 {
    const builtin = @import("builtin");
    const native_os = builtin.os.tag;

    if (native_os == .windows) {
        if (environ.getAlloc(allocator, "APPDATA")) |appdata| {
            defer allocator.free(appdata);
            return try fmt.allocPrint(allocator, "{s}{c}{s}", .{ appdata, Dir.path.sep, appname });
        } else |_| {}
    } else if (native_os == .macos) {
        if (environ.getAlloc(allocator, "HOME")) |home| {
            defer allocator.free(home);
            return try fmt.allocPrint(allocator, "{s}/Library/Application Support/{s}", .{ home, appname });
        } else |_| {}
    } else {
        // Linux/BSD: Use XDG_DATA_HOME or fallback to ~/.local/share
        if (environ.getAlloc(allocator, "XDG_DATA_HOME")) |data_home| {
            defer allocator.free(data_home);
            return try fmt.allocPrint(allocator, "{s}{c}{s}", .{ data_home, Dir.path.sep, appname });
        } else |_| {}
        if (environ.getAlloc(allocator, "HOME")) |home| {
            defer allocator.free(home);
            return try fmt.allocPrint(allocator, "{s}/.local/share/{s}", .{ home, appname });
        } else |_| {}
    }
    return null;
}

fn getDefaultSecretKeyPath(allocator: mem.Allocator, io: Io, environ: process.Environ) !?[]u8 {
    const builtin = @import("builtin");

    // First check MINISIGN_CONFIG_DIR environment variable
    if (environ.getAlloc(allocator, "MINISIGN_CONFIG_DIR")) |config_dir| {
        defer allocator.free(config_dir);
        const path = try fmt.allocPrint(allocator, "{s}{c}minisign.key", .{ config_dir, Dir.path.sep });
        return path;
    } else |_| {}

    // Try $HOME/.minisign/minisign.key
    if (environ.getAlloc(allocator, "HOME")) |home| {
        defer allocator.free(home);
        const path = try fmt.allocPrint(allocator, "{s}{c}.minisign{c}minisign.key", .{ home, Dir.path.sep, Dir.path.sep });
        // Check if file exists, if not continue to next option
        Dir.cwd().access(io, path, .{}) catch {
            allocator.free(path);
            // File doesn't exist, try app data dir (not available on WASI)
            if (builtin.os.tag != .wasi) {
                if (try getAppDataDir(allocator, environ, "minisign")) |app_dir| {
                    defer allocator.free(app_dir);
                    const app_path = try fmt.allocPrint(allocator, "{s}{c}minisign.key", .{ app_dir, Dir.path.sep });
                    return app_path;
                }
            }
            return null;
        };
        return path;
    } else |_| {}

    // Try app data directory (not available on WASI)
    if (builtin.os.tag != .wasi) {
        if (try getAppDataDir(allocator, environ, "minisign")) |app_dir| {
            defer allocator.free(app_dir);
            const path = try fmt.allocPrint(allocator, "{s}{c}minisign.key", .{ app_dir, Dir.path.sep });
            return path;
        }
    }

    // No default available
    return null;
}

fn doit(gpa_allocator: mem.Allocator, args: process.Args, environ: process.Environ) !void {
    var threaded = std.Io.Threaded.init_single_threaded;
    const io = threaded.ioBasic();

    // Verify that the system CSPRNG is properly seeded
    var dummy_byte: [1]u8 = undefined;
    io.randomSecure(&dummy_byte) catch |err| {
        var stderr_writer = File.stderr().writer(io, &.{});
        const stderr = &stderr_writer.interface;
        stderr.print("Error: Failed to obtain secure randomness: {s}\n", .{@errorName(err)}) catch {};
        process.exit(1);
    };

    var res = clap.parse(clap.Help, &params, .{
        .PATH = clap.parsers.string,
        .STRING = clap.parsers.string,
    }, args, .{
        .allocator = gpa_allocator,
    }) catch |err| {
        var buf: [1024]u8 = undefined;
        var stderr_writer = File.stderr().writer(io, &buf);
        const stderr = &stderr_writer.interface;
        stderr.print("Error parsing arguments: {s}\n", .{@errorName(err)}) catch {};
        stderr.flush() catch {};
        usage(io);
    };
    defer res.deinit();

    if (res.args.help != 0) usage(io);
    const quiet = res.args.quiet;
    const prehash: ?bool = if (res.args.legacy != 0) null else true;
    const pk_b64 = res.args.publickey;
    const pk_path = @field(res.args, "publickey-path");
    const sk_path_arg = @field(res.args, "secretkey-path");
    const input_path = res.args.input;
    const output_path = res.args.output;
    const sign_mode = res.args.sign != 0;
    const generate_mode = res.args.generate != 0;
    const recreate_mode = res.args.recreate != 0;
    const change_password_mode = @field(res.args, "change-password") != 0;

    // Determine secret key path (from arg or default)
    const default_sk_path = try getDefaultSecretKeyPath(gpa_allocator, io, environ);
    defer if (default_sk_path) |path| gpa_allocator.free(path);
    const sk_path = sk_path_arg orelse default_sk_path;

    // Handle key generation mode
    if (generate_mode) {
        if (sk_path == null) {
            var stderr_writer = File.stderr().writer(io, &.{});
            stderr_writer.interface.writeAll("Error: Secret key path (-s) is required for key generation\n") catch {};
            usage(io);
        }

        var arena = heap.ArenaAllocator.init(gpa_allocator);
        defer arena.deinit();

        const public_key_path = if (pk_path) |path| path else blk: {
            break :blk try fmt.allocPrint(arena.allocator(), "{s}.pub", .{sk_path.?});
        };

        const sk_exists = if (Dir.cwd().access(io, sk_path.?, .{})) true else |_| false;
        const pk_exists = if (Dir.cwd().access(io, public_key_path, .{})) true else |_| false;

        if (sk_exists or pk_exists) {
            const stderr = File.stderr();
            const stdin = File.stdin();
            var stderr_writer = stderr.writer(io, &.{});
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

            try stderr.writeStreamingAll(io, "Overwrite? (y/N): ");

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
                try Dir.cwd().deleteFile(io, sk_path.?);
            }
            if (pk_exists) {
                try Dir.cwd().deleteFile(io, public_key_path);
            }
        }

        const password = try getPasswordWithPrompt(arena.allocator(), io, "Enter password (leave empty for unencrypted key): ");
        defer arena.allocator().free(password);

        const pwd = if (password.len > 0) password else null;

        try generate(arena.allocator(), io, sk_path.?, public_key_path, pwd);

        if (quiet == 0) {
            var stdout_writer = File.stdout().writer(io, &.{});
            const writer = &stdout_writer.interface;
            try writer.print("Secret key written to {s}\n", .{sk_path.?});
            try writer.print("Public key written to {s}\n", .{public_key_path});
        }
        return;
    }

    if (recreate_mode) {
        if (sk_path == null) {
            var stderr_writer = File.stderr().writer(io, &.{});
            stderr_writer.interface.writeAll("Error: Secret key path (-s) is required for recreating public key\n") catch {};
            usage(io);
        }

        var arena = heap.ArenaAllocator.init(gpa_allocator);
        defer arena.deinit();

        const public_key_path = if (pk_path) |path| path else blk: {
            break :blk try fmt.allocPrint(arena.allocator(), "{s}.pub", .{sk_path.?});
        };

        const pk_exists = if (Dir.cwd().access(io, public_key_path, .{})) true else |_| false;
        if (pk_exists) {
            const stderr = File.stderr();
            const stdin = File.stdin();
            var stderr_writer = stderr.writer(io, &.{});
            const writer = &stderr_writer.interface;

            try writer.print("Warning: Public key file already exists: {s}\n", .{public_key_path});
            try stderr.writeStreamingAll(io, "Overwrite? (y/N): ");

            var response_buf: [10]u8 = undefined;
            var reader = stdin.reader(io, &response_buf);
            const response = reader.interface.takeDelimiterExclusive('\n') catch "";

            const trimmed = mem.trim(u8, response, &std.ascii.whitespace);
            if (!mem.eql(u8, trimmed, "y") and !mem.eql(u8, trimmed, "Y")) {
                try writer.writeAll("Aborted.\n");
                process.exit(1);
            }

            try Dir.cwd().deleteFile(io, public_key_path);
        }

        var sk = try SecretKey.fromFile(arena.allocator(), sk_path.?, io);
        defer sk.deinit();

        if (mem.eql(u8, &sk.kdf_algorithm, "Sc")) {
            const password = try getPasswordWithPrompt(arena.allocator(), io, "Password: ");
            defer arena.allocator().free(password);
            try sk.decrypt(arena.allocator(), password);
        }

        try sk.getPublicKey().toFile(io, public_key_path);

        if (quiet == 0) {
            var stdout_writer = File.stdout().writer(io, &.{});
            try stdout_writer.interface.print("Public key recreated and written to {s}\n", .{public_key_path});
        }
        return;
    }

    if (change_password_mode) {
        if (sk_path == null) {
            var stderr_writer = File.stderr().writer(io, &.{});
            stderr_writer.interface.writeAll("Error: Secret key path (-s) is required for changing password\n") catch {};
            usage(io);
        }

        var arena = heap.ArenaAllocator.init(gpa_allocator);
        defer arena.deinit();

        changePassword(arena.allocator(), io, sk_path.?) catch |err| {
            var stderr_writer = File.stderr().writer(io, &.{});
            if (err == error.PasswordMismatch) {
                stderr_writer.interface.writeAll("Error: Passwords don't match\n") catch {};
            } else if (err == error.WrongPassword) {
                stderr_writer.interface.writeAll("Error: Wrong password\n") catch {};
            } else {
                stderr_writer.interface.print("Error: {}\n", .{err}) catch {};
            }
            process.exit(1);
        };

        if (quiet == 0) {
            var stdout_writer = File.stdout().writer(io, &.{});
            try stdout_writer.interface.print("Password changed for {s}\n", .{sk_path.?});
        }
        return;
    }

    if (sign_mode) {
        if (input_path.len == 0) usage(io);
        if (sk_path == null) {
            var stderr_writer = File.stderr().writer(io, &.{});
            stderr_writer.interface.writeAll("Error: Secret key path is required for signing\n") catch {};
            usage(io);
        }
        if (output_path != null and input_path.len > 1) {
            var stderr_writer = File.stderr().writer(io, &.{});
            stderr_writer.interface.writeAll("Error: Cannot use -o with multiple input files\n") catch {};
            usage(io);
        }

        var arena = heap.ArenaAllocator.init(gpa_allocator);
        defer arena.deinit();

        var sk = try SecretKey.fromFile(arena.allocator(), sk_path.?, io);
        defer sk.deinit();

        if (mem.eql(u8, &sk.kdf_algorithm, "Sc")) {
            const password = try getPasswordWithPrompt(arena.allocator(), io, "Password: ");
            defer arena.allocator().free(password);
            try sk.decrypt(arena.allocator(), password);
        }

        const trusted_comment = if (@field(res.args, "trusted-comment")) |tc| tc else blk: {
            const now = try Io.Clock.Timestamp.now(io, .real);
            const timestamp = now.raw.toSeconds();
            break :blk try fmt.allocPrint(arena.allocator(), "timestamp:{d}", .{timestamp});
        };

        const untrusted_comment = if (@field(res.args, "untrusted-comment")) |uc| uc else "signature from minizign secret key";

        for (input_path) |file_path| {
            const sig_path = if (output_path) |path| path else blk: {
                break :blk try fmt.allocPrint(arena.allocator(), "{s}.minisig", .{file_path});
            };

            const fd = try Dir.cwd().openFile(io, file_path, .{});
            defer fd.close(io);
            var signature = try sk.signFile(arena.allocator(), io, fd, true, trusted_comment);
            defer signature.deinit();
            try signature.toFile(io, sig_path, untrusted_comment);

            if (quiet == 0) {
                var stdout_writer = File.stdout().writer(io, &.{});
                try stdout_writer.interface.print("Signature written to {s}\n", .{sig_path});
            }
        }
        return;
    }

    // Handle conversion mode
    if (pk_path == null and pk_b64 == null) {
        usage(io);
    }
    var pks_buf: [64]PublicKey = undefined;
    const pks = if (pk_b64) |b64| blk: {
        pks_buf[0] = try PublicKey.decodeFromBase64(b64);
        break :blk pks_buf[0..1];
    } else try PublicKey.fromFile(gpa_allocator, &pks_buf, pk_path.?, io);

    if (res.args.convert != 0) {
        const ssh_key = pks[0].getSshKey();
        const fd = File.stdout();
        try fd.writeStreamingAll(io, &ssh_key);
        return;
    }

    // Handle verification mode
    if (input_path.len == 0) {
        usage(io);
    }
    const verify_input_path = input_path[0];
    var arena = heap.ArenaAllocator.init(gpa_allocator);
    defer arena.deinit();
    const sig_path = if (output_path) |path| path else try fmt.allocPrint(arena.allocator(), "{s}.minisig", .{verify_input_path});
    const sig = Signature.fromFile(arena.allocator(), sig_path, io) catch |err| {
        if (quiet == 0) {
            var stderr_writer = File.stderr().writer(io, &.{});
            if (err == error.UnprintableCharacters) {
                stderr_writer.interface.writeAll("Signature file contains unprintable characters\n") catch {};
            } else {
                stderr_writer.interface.print("Error reading signature file: {}\n", .{err}) catch {};
            }
        }
        process.exit(1);
    };
    if (verify(arena.allocator(), io, pks, verify_input_path, sig, prehash)) {
        if (quiet == 0) {
            var stdout_writer = File.stdout().writer(io, &.{});
            try stdout_writer.interface.print("Signature and comment signature verified\nTrusted comment: {s}\n", .{sig.trusted_comment});
        }
    } else |err| {
        if (quiet == 0) {
            var stderr_writer = File.stderr().writer(io, &.{});
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

pub fn main(init: process.Init.Minimal) !void {
    var gpa = heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    try doit(gpa.allocator(), init.args, init.environ);
}
