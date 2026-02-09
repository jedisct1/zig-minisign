const std = @import("std");
const base64 = std.base64;
const crypto = std.crypto;
const fmt = std.fmt;
const heap = std.heap;
const Io = std.Io;
const math = std.math;
const mem = std.mem;
const os = std.os;
const process = std.process;
const unicode = std.unicode;
const Dir = Io.Dir;
const File = Io.File;
const Blake2b256 = crypto.hash.blake2.Blake2b256;
const Blake2b512 = crypto.hash.blake2.Blake2b512;
const Ed25519 = crypto.sign.Ed25519;
const Endian = std.builtin.Endian;

fn isPrintable(s: []const u8) bool {
    const view = unicode.Utf8View.init(s) catch return false;
    var it = view.iterator();
    while (it.nextCodepoint()) |cp| {
        if (cp == '\t') continue;
        if (cp <= 0x1f or (cp >= 0x7f and cp <= 0x9f)) return false;
    }
    return true;
}

pub const Signature = struct {
    arena: heap.ArenaAllocator,
    untrusted_comment: []u8,
    signature_algorithm: [2]u8,
    key_id: [8]u8,
    signature: [64]u8,
    trusted_comment: []u8,
    global_signature: [64]u8,

    pub fn deinit(self: *Signature) void {
        self.arena.deinit();
    }

    pub const Algorithm = enum { Prehash, Legacy };

    pub fn algorithm(sig: Signature) !Algorithm {
        const signature_algorithm = sig.signature_algorithm;
        const prehashed = if (signature_algorithm[0] == 0x45 and signature_algorithm[1] == 0x64) false else if (signature_algorithm[0] == 0x45 and signature_algorithm[1] == 0x44) true else return error.UnsupportedAlgorithm;
        return if (prehashed) .Prehash else .Legacy;
    }

    pub fn decode(child_allocator: mem.Allocator, lines_str: []const u8) !Signature {
        var arena = heap.ArenaAllocator.init(child_allocator);
        errdefer arena.deinit();
        const allocator = arena.allocator();
        var it = mem.tokenizeScalar(u8, lines_str, '\n');
        const untrusted_comment = try allocator.dupe(u8, mem.trim(u8, it.next() orelse return error.InvalidEncoding, " \t\r\n"));
        var bin1: [74]u8 = undefined;
        try base64.standard.Decoder.decode(&bin1, mem.trim(u8, it.next() orelse return error.InvalidEncoding, " \t\r\n"));
        const trusted_comment_line = mem.trim(u8, it.next() orelse return error.InvalidEncoding, " \t\r\n");
        if (!mem.startsWith(u8, trusted_comment_line, "trusted comment: ")) {
            return error.InvalidEncoding;
        }
        const trusted_comment_raw = trusted_comment_line["trusted comment: ".len..];
        if (!isPrintable(trusted_comment_raw)) {
            return error.UnprintableCharacters;
        }
        const trusted_comment = try allocator.dupe(u8, trusted_comment_raw);
        var bin2: [64]u8 = undefined;
        try base64.standard.Decoder.decode(&bin2, mem.trim(u8, it.next() orelse return error.InvalidEncoding, " \t\r\n"));
        const sig = Signature{
            .arena = arena,
            .untrusted_comment = untrusted_comment,
            .signature_algorithm = bin1[0..2].*,
            .key_id = bin1[2..10].*,
            .signature = bin1[10..74].*,
            .trusted_comment = trusted_comment,
            .global_signature = bin2,
        };
        return sig;
    }

    pub fn fromFile(allocator: mem.Allocator, path: []const u8, io: Io) !Signature {
        const fd = try Dir.cwd().openFile(io, path, .{});
        defer fd.close(io);
        var file_reader = fd.reader(io, &.{});
        const sig_str = try file_reader.interface.allocRemaining(allocator, .limited(4096));
        defer allocator.free(sig_str);
        return Signature.decode(allocator, sig_str);
    }

    pub fn toFile(self: *const Signature, io: Io, path: []const u8, untrusted_comment: []const u8) !void {
        const fd = try Dir.cwd().createFile(io, path, .{});
        defer fd.close(io);

        var buf: [4096]u8 = undefined;
        var file_writer = fd.writer(io, &buf);
        const writer = &file_writer.interface;

        // Write untrusted comment
        const comment_prefix = "untrusted comment: ";
        try writer.writeAll(comment_prefix);
        try writer.writeAll(untrusted_comment);
        try writer.writeAll("\n");

        // Write signature (base64 encoded)
        var sig_bin: [74]u8 = undefined;
        @memcpy(sig_bin[0..2], &self.signature_algorithm);
        @memcpy(sig_bin[2..10], &self.key_id);
        @memcpy(sig_bin[10..74], &self.signature);

        const Base64Encoder = base64.standard.Encoder;
        var sig_b64: [Base64Encoder.calcSize(74)]u8 = undefined;
        _ = Base64Encoder.encode(&sig_b64, &sig_bin);
        try writer.writeAll(&sig_b64);
        try writer.writeAll("\n");

        // Write trusted comment
        const trusted_prefix = "trusted comment: ";
        try writer.writeAll(trusted_prefix);
        try writer.writeAll(self.trusted_comment);
        try writer.writeAll("\n");

        // Write global signature (base64 encoded)
        var global_b64: [Base64Encoder.calcSize(64)]u8 = undefined;
        _ = Base64Encoder.encode(&global_b64, &self.global_signature);
        try writer.writeAll(&global_b64);
        try writer.writeAll("\n");

        try writer.flush();
    }
};

pub const PublicKey = struct {
    untrusted_comment: ?[]u8 = null,
    signature_algorithm: [2]u8 = "Ed".*,
    key_id: [8]u8,
    key: [key_length]u8,

    const key_length = 32;
    const key_type = "ssh-ed25519";
    const key_id_prefix = "minisign key ";

    pub fn decodeFromBase64(str: []const u8) !PublicKey {
        if (str.len != 56) {
            return error.InvalidEncoding;
        }
        var bin: [42]u8 = undefined;
        try base64.standard.Decoder.decode(&bin, str);
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

    pub fn decodeFromSsh(pks: []PublicKey, lines: []const u8) ![]PublicKey {
        var lines_it = mem.tokenizeScalar(u8, lines, '\n');
        var i: usize = 0;
        while (lines_it.next()) |line| {
            var pk = PublicKey{ .key_id = @splat(0), .key = undefined };

            var it = mem.tokenizeScalar(u8, line, ' ');
            const header = it.next() orelse return error.InvalidEncoding;
            if (!mem.eql(u8, key_type, header)) {
                return error.InvalidEncoding;
            }
            const encoded_ssh_key = it.next() orelse return error.InvalidEncoding;
            const pk_len = pk.key.len;
            var ssh_key: [4 + key_type.len + 4 + pk_len]u8 = undefined;
            try base64.standard.Decoder.decode(&ssh_key, encoded_ssh_key);
            if (mem.readInt(u32, ssh_key[0..4], Endian.big) != key_type.len or
                !mem.eql(u8, ssh_key[4..][0..key_type.len], key_type) or
                mem.readInt(u32, ssh_key[4 + key_type.len ..][0..4], Endian.big) != pk.key.len)
            {
                return error.InvalidEncoding;
            }
            @memcpy(&pk.key, ssh_key[4 + key_type.len + 4 ..]);

            const rest = mem.trim(u8, it.rest(), " \t\r\n");
            if (mem.startsWith(u8, rest, key_id_prefix) and rest.len > key_id_prefix.len) {
                mem.writeInt(u64, &pk.key_id, try fmt.parseInt(u64, rest[key_id_prefix.len..], 16), Endian.little);
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

    pub fn decode(pks: []PublicKey, lines_str: []const u8) ![]PublicKey {
        if (decodeFromSsh(pks, lines_str)) |pks_| return pks_ else |_| {}

        var it = mem.tokenizeScalar(u8, lines_str, '\n');
        _ = it.next() orelse return error.InvalidEncoding;
        const encoded_key = mem.trim(u8, it.next() orelse return error.InvalidEncoding, " \t\r\n");
        const pk = try decodeFromBase64(encoded_key);
        pks[0] = pk;
        return pks[0..1];
    }

    pub fn fromFile(allocator: mem.Allocator, pks: []PublicKey, path: []const u8, io: Io) ![]PublicKey {
        const fd = try Dir.cwd().openFile(io, path, .{});
        defer fd.close(io);
        var file_reader = fd.reader(io, &.{});
        const pk_str = try file_reader.interface.allocRemaining(allocator, .limited(4096));
        defer allocator.free(pk_str);
        return PublicKey.decode(pks, pk_str);
    }

    pub fn verifier(self: *const PublicKey, sig: *const Signature) !Verifier {
        const key_id_len = self.key_id.len;
        const null_key_id: [key_id_len]u8 = @splat(0);
        if (!mem.eql(u8, &null_key_id, &self.key_id) and !mem.eql(u8, &sig.key_id, &self.key_id)) {
            return error.KeyIdMismatch;
        }

        const ed25519_pk = try Ed25519.PublicKey.fromBytes(self.key);

        return Verifier{
            .pk = self,
            .sig = sig,
            .format = switch (try sig.algorithm()) {
                .Prehash => .{ .Prehash = Blake2b512.init(.{}) },
                .Legacy => .{ .Legacy = try Ed25519.Signature.fromBytes(sig.signature).verifier(ed25519_pk) },
            },
        };
    }

    pub fn verifyFile(self: PublicKey, allocator: std.mem.Allocator, io: Io, fd: File, sig: Signature, prehash: ?bool) !void {
        var v = try self.verifier(&sig);

        if (prehash) |want_prehashed| {
            if (want_prehashed and v.format != .Prehash) {
                return error.SignatureVerificationFailed;
            }
        }

        var read_buf: [heap.page_size_max]u8 = undefined;
        var reader = fd.reader(io, &read_buf);
        var buf: [heap.page_size_max]u8 = undefined;
        while (true) {
            const read_nb = try reader.interface.readSliceShort(&buf);
            if (read_nb == 0) break;
            v.update(buf[0..read_nb]);
        }
        try v.verify(allocator);
    }

    pub fn getSshKeyLength() usize {
        const bin_len = 4 + key_type.len + 4 + key_length;
        const encoded_key_len = base64.standard.Encoder.calcSize(bin_len);

        return key_type.len + 1 + encoded_key_len + 1 + key_id_prefix.len + 16 + 1;
    }

    pub fn getSshKey(pk: PublicKey) [getSshKeyLength()]u8 {
        var ssh_key: [PublicKey.getSshKeyLength()]u8 = undefined;
        pk.encodeToSsh(&ssh_key);
        return ssh_key;
    }

    pub fn encodeToSsh(pk: PublicKey, buffer: *[getSshKeyLength()]u8) void {
        var ssh_key: [4 + key_type.len + 4 + key_length]u8 = undefined;
        mem.writeInt(u32, ssh_key[0..4], key_type.len, Endian.big);
        @memcpy(ssh_key[4..][0..key_type.len], key_type);
        mem.writeInt(u32, ssh_key[4 + key_type.len ..][0..4], pk.key.len, Endian.big);
        @memcpy(ssh_key[4 + key_type.len + 4 ..], &pk.key);

        const Base64Encoder = base64.standard.Encoder;
        var encoded_ssh_key: [Base64Encoder.calcSize(ssh_key.len)]u8 = undefined;
        _ = Base64Encoder.encode(&encoded_ssh_key, &ssh_key);

        _ = fmt.bufPrint(buffer, "{s} {s} {s}{X}\n", .{ key_type, encoded_ssh_key, key_id_prefix, mem.readInt(u64, &pk.key_id, Endian.little) }) catch unreachable;
    }

    pub fn toFile(self: PublicKey, io: Io, path: []const u8) !void {
        const fd = try Dir.cwd().createFile(io, path, .{ .exclusive = true });
        defer fd.close(io);

        var buf: [256]u8 = undefined;
        var file_writer = fd.writer(io, &buf);
        const writer = &file_writer.interface;

        // Write untrusted comment
        const comment = "untrusted comment: minisign public key";
        try writer.writeAll(comment);
        try writer.writeAll("\n");

        // Encode and write public key
        var bin: [42]u8 = undefined;
        @memcpy(bin[0..2], &self.signature_algorithm);
        @memcpy(bin[2..10], &self.key_id);
        @memcpy(bin[10..42], &self.key);

        const Base64Encoder = base64.standard.Encoder;
        var encoded: [Base64Encoder.calcSize(42)]u8 = undefined;
        _ = Base64Encoder.encode(&encoded, &bin);
        try writer.writeAll(&encoded);
        try writer.writeAll("\n");

        try writer.flush();
    }
};

pub const Verifier = struct {
    pk: *const PublicKey,
    sig: *const Signature,
    format: union(enum) {
        Prehash: Blake2b512,
        Legacy: Ed25519.Verifier,
    },

    pub fn update(self: *Verifier, bytes: []const u8) void {
        switch (self.format) {
            .Prehash => |*prehash| prehash.update(bytes),
            .Legacy => |*legacy| legacy.update(bytes),
        }
    }

    pub fn verify(self: *Verifier, allocator: std.mem.Allocator) !void {
        const ed25519_pk = try Ed25519.PublicKey.fromBytes(self.pk.key);
        switch (self.format) {
            .Prehash => |*prehash| {
                var digest: [64]u8 = undefined;

                prehash.final(&digest);

                try Ed25519.Signature.fromBytes(self.sig.signature).verify(&digest, ed25519_pk);
            },
            .Legacy => |*legacy| {
                try legacy.verify();
            },
        }

        var global = try allocator.alloc(u8, self.sig.signature.len + self.sig.trusted_comment.len);
        defer allocator.free(global);
        @memcpy(global[0..self.sig.signature.len], self.sig.signature[0..]);
        @memcpy(global[self.sig.signature.len..], self.sig.trusted_comment);
        try Ed25519.Signature.fromBytes(self.sig.global_signature).verify(global, ed25519_pk);
    }
};

pub const SecretKey = struct {
    arena: heap.ArenaAllocator,
    untrusted_comment: []u8,
    signature_algorithm: [2]u8,
    kdf_algorithm: [2]u8,
    checksum_algorithm: [2]u8,
    kdf_salt: [32]u8,
    kdf_opslimit: u64,
    kdf_memlimit: u64,
    key_id: [8]u8,
    secret_key: [64]u8,
    checksum: [32]u8,

    pub fn deinit(self: *SecretKey) void {
        crypto.secureZero(u8, &self.secret_key);
        crypto.secureZero(u8, &self.checksum);
        self.arena.deinit();
    }

    pub fn decode(child_allocator: mem.Allocator, lines_str: []const u8) !SecretKey {
        var arena = heap.ArenaAllocator.init(child_allocator);
        errdefer arena.deinit();
        const allocator = arena.allocator();

        var it = mem.tokenizeScalar(u8, lines_str, '\n');
        const untrusted_comment = try allocator.dupe(u8, mem.trim(u8, it.next() orelse return error.InvalidEncoding, " \t\r\n"));

        const encoded_key = mem.trim(u8, it.next() orelse return error.InvalidEncoding, " \t\r\n");

        // The secret key structure is 158 bytes total:
        // 2 (sig_alg) + 2 (kdf_alg) + 2 (chk_alg) + 32 (salt) + 8 (opslimit) + 8 (memlimit) + 8 (keynum) + 64 (sk) + 32 (chk) = 158 bytes
        // The encrypted part is: 8 (keynum) + 64 (sk) + 32 (chk) = 104 bytes
        // Total in file: 2 + 2 + 2 + 32 + 8 + 8 + 104 = 158 bytes
        var bin: [158]u8 = undefined;
        try base64.standard.Decoder.decode(&bin, encoded_key);

        var sk = SecretKey{
            .arena = arena,
            .untrusted_comment = untrusted_comment,
            .signature_algorithm = bin[0..2].*,
            .kdf_algorithm = bin[2..4].*,
            .checksum_algorithm = bin[4..6].*,
            .kdf_salt = bin[6..38].*,
            .kdf_opslimit = mem.readInt(u64, bin[38..46], Endian.little),
            .kdf_memlimit = mem.readInt(u64, bin[46..54], Endian.little),
            .key_id = bin[54..62].*,
            .secret_key = bin[62..126].*,
            .checksum = bin[126..158].*,
        };

        if (!mem.eql(u8, &sk.signature_algorithm, "Ed")) {
            return error.UnsupportedAlgorithm;
        }
        if (!mem.eql(u8, &sk.checksum_algorithm, "B2")) {
            return error.UnsupportedChecksumAlgorithm;
        }

        return sk;
    }

    pub fn fromFile(allocator: mem.Allocator, path: []const u8, io: Io) !SecretKey {
        const fd = try Dir.cwd().openFile(io, path, .{});
        defer fd.close(io);
        var file_reader = fd.reader(io, &.{});
        const sk_str = try file_reader.interface.allocRemaining(allocator, .limited(4096));
        defer allocator.free(sk_str);
        return SecretKey.decode(allocator, sk_str);
    }

    fn xorData(self: *SecretKey, stream: []const u8) void {
        var data: [104]u8 = undefined;
        @memcpy(data[0..8], &self.key_id);
        @memcpy(data[8..72], &self.secret_key);
        @memcpy(data[72..104], &self.checksum);

        for (&data, stream) |*byte, key| byte.* ^= key;

        @memcpy(&self.key_id, data[0..8]);
        @memcpy(&self.secret_key, data[8..72]);
        @memcpy(&self.checksum, data[72..104]);
    }

    pub fn decrypt(self: *SecretKey, allocator: mem.Allocator, password: []const u8) !void {
        if (mem.eql(u8, &self.kdf_algorithm, "\x00\x00")) return;
        if (!mem.eql(u8, &self.kdf_algorithm, "Sc")) return error.UnsupportedKdfAlgorithm;

        var stream: [104]u8 = undefined;
        defer crypto.secureZero(u8, &stream);

        const params = crypto.pwhash.scrypt.Params.fromLimits(self.kdf_opslimit, @intCast(self.kdf_memlimit));
        try crypto.pwhash.scrypt.kdf(allocator, &stream, password, &self.kdf_salt, params);

        self.xorData(&stream);

        // Verify checksum
        var computed_checksum: [32]u8 = undefined;
        var hasher = Blake2b256.init(.{});
        hasher.update(&self.signature_algorithm);
        hasher.update(&self.key_id);
        hasher.update(&self.secret_key);
        hasher.final(&computed_checksum);

        if (!crypto.timing_safe.eql([32]u8, computed_checksum, self.checksum)) {
            crypto.secureZero(u8, &self.secret_key);
            return error.WrongPassword;
        }
    }

    pub fn signFile(
        self: *const SecretKey,
        allocator: mem.Allocator,
        io: Io,
        fd: File,
        prehash: bool,
        trusted_comment: []const u8,
    ) !Signature {
        if (!prehash) return error.LegacySigningNotImplemented;

        var message: [64]u8 = undefined;
        var hasher = Blake2b512.init(.{});
        var read_buf: [heap.page_size_max]u8 = undefined;
        var reader = fd.reader(io, &read_buf);
        var buf: [heap.page_size_max]u8 = undefined;
        while (true) {
            const read_nb = try reader.interface.readSliceShort(&buf);
            if (read_nb == 0) break;
            hasher.update(buf[0..read_nb]);
        }
        hasher.final(&message);

        const ed25519_sk = Ed25519.SecretKey{ .bytes = self.secret_key };
        const keypair = Ed25519.KeyPair{
            .public_key = try Ed25519.PublicKey.fromBytes(ed25519_sk.publicKeyBytes()),
            .secret_key = ed25519_sk,
        };

        const sig_bytes = try keypair.sign(&message, null);

        const global_data = try allocator.alloc(u8, 64 + trusted_comment.len);
        defer allocator.free(global_data);
        @memcpy(global_data[0..64], &sig_bytes.toBytes());
        @memcpy(global_data[64..], trusted_comment);

        var sig_arena = heap.ArenaAllocator.init(allocator);
        errdefer sig_arena.deinit();

        return Signature{
            .arena = sig_arena,
            .untrusted_comment = try sig_arena.allocator().dupe(u8, ""),
            .signature_algorithm = "ED".*,
            .key_id = self.key_id,
            .signature = sig_bytes.toBytes(),
            .trusted_comment = try sig_arena.allocator().dupe(u8, trusted_comment),
            .global_signature = (try keypair.sign(global_data, null)).toBytes(),
        };
    }

    pub fn getPublicKey(self: *const SecretKey) PublicKey {
        const pk_bytes = self.secret_key[32..64];
        return PublicKey{
            .signature_algorithm = "Ed".*,
            .key_id = self.key_id,
            .key = pk_bytes.*,
        };
    }

    pub fn generate(allocator: mem.Allocator, io: std.Io) !SecretKey {
        // Generate Ed25519 keypair
        const keypair = Ed25519.KeyPair.generate(io);

        // Generate random key ID
        var key_id: [8]u8 = undefined;
        io.random(&key_id);

        // The Ed25519 secret key already contains seed (32) + public key (32) = 64 bytes
        const secret_key = keypair.secret_key.bytes;

        // Compute checksum: Blake2b-256(signature_algorithm || key_id || secret_key)
        var checksum: [32]u8 = undefined;
        var hasher = Blake2b256.init(.{});
        const sig_alg = "Ed".*;
        hasher.update(&sig_alg);
        hasher.update(&key_id);
        hasher.update(&secret_key);
        hasher.final(&checksum);

        var arena = heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        return SecretKey{
            .arena = arena,
            .untrusted_comment = try arena.allocator().dupe(u8, "untrusted comment: minisign encrypted secret key"),
            .signature_algorithm = sig_alg,
            .kdf_algorithm = "\x00\x00".*, // Unencrypted by default
            .checksum_algorithm = "B2".*,
            .kdf_salt = @splat(0),
            .kdf_opslimit = 0,
            .kdf_memlimit = 0,
            .key_id = key_id,
            .secret_key = secret_key,
            .checksum = checksum,
        };
    }

    pub fn encrypt(self: *SecretKey, allocator: mem.Allocator, io: std.Io, password: []const u8) !void {
        if (password.len == 0) return error.EmptyPassword;

        io.random(&self.kdf_salt);
        self.kdf_opslimit = 524288;
        self.kdf_memlimit = 16777216;

        var stream: [104]u8 = undefined;
        defer crypto.secureZero(u8, &stream);

        const params = crypto.pwhash.scrypt.Params.fromLimits(self.kdf_opslimit, @intCast(self.kdf_memlimit));
        try crypto.pwhash.scrypt.kdf(allocator, &stream, password, &self.kdf_salt, params);

        self.xorData(&stream);
        self.kdf_algorithm = "Sc".*;
    }

    pub fn toFile(self: *const SecretKey, io: Io, path: []const u8) !void {
        const builtin = @import("builtin");
        // Use restrictive permissions on Unix (0o600 = owner read/write only)
        // On Windows, use default file attributes (ACLs are handled differently)
        const permissions: File.Permissions = if (builtin.os.tag != .windows)
            File.Permissions.fromMode(0o600)
        else
            .default_file;
        const fd = try Dir.cwd().createFile(io, path, .{ .exclusive = true, .permissions = permissions });
        defer fd.close(io);

        var buf: [4096]u8 = undefined;
        var file_writer = fd.writer(io, &buf);
        const writer = &file_writer.interface;

        // Write untrusted comment
        try writer.writeAll(self.untrusted_comment);
        try writer.writeAll("\n");

        // Encode secret key
        var bin: [158]u8 = undefined;
        @memcpy(bin[0..2], &self.signature_algorithm);
        @memcpy(bin[2..4], &self.kdf_algorithm);
        @memcpy(bin[4..6], &self.checksum_algorithm);
        @memcpy(bin[6..38], &self.kdf_salt);
        mem.writeInt(u64, bin[38..46], self.kdf_opslimit, Endian.little);
        mem.writeInt(u64, bin[46..54], self.kdf_memlimit, Endian.little);
        @memcpy(bin[54..62], &self.key_id);
        @memcpy(bin[62..126], &self.secret_key);
        @memcpy(bin[126..158], &self.checksum);

        const Base64Encoder = base64.standard.Encoder;
        var encoded: [Base64Encoder.calcSize(158)]u8 = undefined;
        _ = Base64Encoder.encode(&encoded, &bin);
        try writer.writeAll(&encoded);
        try writer.writeAll("\n");

        try writer.flush();
    }
};
