const std = @import("std");

pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    const minizign_module = b.addModule("minizign", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    const resolved_target = target.result;
    const is_freestanding = resolved_target.os.tag == .freestanding;

    // Skip building the CLI executable for freestanding targets (e.g., WASM)
    // since it requires OS features like file I/O, stdin/stdout, and process control
    if (!is_freestanding) {
        // Build minzign cli
        const exe = b.addExecutable(.{
            .name = "minizign",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/main.zig"),
                .target = target,
                .optimize = optimize,
            }),
        });

        exe.root_module.addImport("minizign", minizign_module);

        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());

        if (b.args) |args| {
            run_cmd.addArgs(args);
        }

        const run_step = b.step("run", "Run the app");
        run_step.dependOn(&run_cmd.step);
    }

    const lib_unit_tests = b.addTest(.{
        .root_module = minizign_module,
    });
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);

    // Build a webassembly module. Does not use the standard optimize and
    // target options.
    {
        const target_wasm32 = b.resolveTargetQuery(.{
            .cpu_arch = .wasm32,
            .os_tag = .freestanding,
        });

        const wasm = b.addExecutable(.{
            .name = "minizign",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/wasm.zig"),
                .target = target_wasm32,
                .optimize = .ReleaseSmall,
            }),
        });

        wasm.root_module.addImport("minizign", minizign_module);

        wasm.entry = .disabled;
        wasm.export_memory = true;
        wasm.root_module.export_symbol_names = &.{
            "allocate",
            "free",
            "signatureDecode",
            "signatureGetTrustedComment",
            "signatureGetTrustedCommentLength",
            "signatureDeinit",
            "publicKeyDecodeFromBase64",
            "publicKeyDecodeFromSsh",
            "publicKeyDeinit",
            "publicKeyVerifier",
            "verifierUpdate",
            "verifierVerify",
            "verifierDeinit",
        };

        const installWasm = b.addInstallArtifact(wasm, .{});
        b.getInstallStep().dependOn(&installWasm.step);
    }
}
