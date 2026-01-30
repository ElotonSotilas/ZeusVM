const std = @import("std");
const ZeusVM = @import("ZeusVM");
const bootstrap = ZeusVM.bootstrap;
const host = @import("host.zig");

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var memory_size: usize = 1024 * 1024; // Default 1MB
    var target_file: ?[]const u8 = null;
    var output_file: ?[]const u8 = null;
    var program_args = std.ArrayList([]const u8).empty;
    defer program_args.deinit(allocator);
    var force_run = false;
    var use_jit = true;
    var jit_threshold: u32 = 50;

    // Parse arguments
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.eql(u8, arg, "-m") or std.mem.eql(u8, arg, "--mem")) {
            if (i + 1 >= args.len) {
                std.debug.print("Error: {s} requires a size argument\n", .{arg});
                return error.ArgumentsError;
            }
            memory_size = parseSize(args[i + 1]) catch {
                std.debug.print("Error: Invalid size format '{s}'\n", .{args[i + 1]});
                return error.ArgumentsError;
            };
            i += 1;
        } else if (std.mem.eql(u8, arg, "-o")) {
            if (i + 1 >= args.len) {
                std.debug.print("Error: -o requires a filename argument\n", .{});
                return error.ArgumentsError;
            }
            output_file = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--run")) {
            force_run = true;
        } else if (std.mem.eql(u8, arg, "--no-jit")) {
            use_jit = false;
        } else if (std.mem.eql(u8, arg, "--jit-threshold")) {
            if (i + 1 >= args.len) {
                std.debug.print("Error: --jit-threshold requires a value\n", .{});
                return error.ArgumentsError;
            }
            jit_threshold = std.fmt.parseInt(u32, args[i + 1], 10) catch {
                std.debug.print("Error: Invalid threshold '{s}'\n", .{args[i + 1]});
                return error.ArgumentsError;
            };
            i += 1;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            if (target_file == null) {
                std.debug.print("Error: Unknown flag '{s}'\n", .{arg});
                return error.ArgumentsError;
            } else {
                try program_args.append(allocator, arg);
            }
        } else {
            // First non-flag argument is the target file
            if (target_file == null) {
                target_file = arg;
            } else {
                try program_args.append(allocator, arg);
            }
        }
    }

    if (target_file == null) {
        std.debug.print("Usage: {s} [flags] <file.zeus|.zar|.zs> [args...]\n", .{args[0]});
        std.debug.print("Flags:\n", .{});
        std.debug.print("  -m, --mem <size>    Set VM memory size (default 1MB)\n", .{});
        std.debug.print("  -o <file>           Output file for assembler\n", .{});
        std.debug.print("  --run               Force execution (runs .zs after assembly)\n", .{});
        std.debug.print("  --no-jit            Disable JIT compilation\n", .{});
        std.debug.print("  --jit-threshold <n> Set JIT hotness threshold (default 50)\n", .{});
        return error.UsageHelp;
    }

    const filename = target_file.?;

    const is_zs = std.mem.endsWith(u8, filename, ".zs");
    const mode_compile = is_zs and !force_run;

    // Handle Assembly
    var assembly_code: ?[]u8 = null;
    defer if (assembly_code) |code| allocator.free(code);

    if (is_zs) {
        const source = std.fs.cwd().readFileAlloc(allocator, filename, 1024 * 1024) catch |err| {
            std.debug.print("Error reading assembly file '{s}': {}\n", .{ filename, err });
            return error.FileReadError;
        };
        defer allocator.free(source);

        var assem = ZeusVM.assembler.Assembler.init(allocator, source);
        defer assem.deinit();

        assembly_code = assem.assemble() catch |err| {
            std.debug.print("Error assembling file '{s}': {}\n", .{ filename, err });
            return error.AssemblyError;
        };

        if (mode_compile) {
            const out_name = output_file orelse try std.fmt.allocPrint(allocator, "{s}.zeus", .{std.fs.path.stem(filename)});
            defer if (output_file == null) allocator.free(out_name);

            const out_file = try std.fs.cwd().createFile(out_name, .{});
            defer out_file.close();

            try out_file.writeAll(assembly_code.?);
            std.debug.print("Assembled {s} successfully -> {s} ({} bytes)\n", .{ filename, out_name, assembly_code.?.len });
            return;
        }
    }

    const file: ?std.fs.File = if (assembly_code == null) (std.fs.cwd().openFile(filename, .{}) catch |err| {
        std.debug.print("Error opening file '{s}': {}\n", .{ filename, err });
        return error.FileOpenError;
    }) else null;
    defer if (file) |f| f.close();

    const file_len = if (file) |f| try f.getEndPos() else if (assembly_code) |code| code.len else 0;
    if (file_len > memory_size and !std.mem.endsWith(u8, filename, ".zar")) {
        std.debug.print("Error: File larger than memory size ({} > {})\n", .{ file_len, memory_size });
        return error.MemoryTooSmall;
    }

    // Allocate VM memory
    const memory = try allocator.alloc(u8, memory_size);
    defer allocator.free(memory);
    @memset(memory, 0);

    // Load Content
    var end_of_main: u64 = 0;
    var tmp_name_buf: [64]u8 = undefined;

    // Filesystem Root Setup
    var fs_root = std.fs.cwd();
    var fs_root_needs_close = false;
    var cleanup_parent: ?std.fs.Dir = null;
    var cleanup_path: []const u8 = "";

    // Defer cleanup (LIFO order: close root -> delete tree -> close parent)
    defer {
        if (fs_root_needs_close) fs_root.close();
        if (cleanup_parent) |dir| {
            var d = dir;
            d.deleteTree(cleanup_path) catch {};
            d.close();
        }
    }
    if (std.mem.endsWith(u8, filename, ".zar")) {
        if (is_zs) {
            std.debug.print("Error: Assembler is not compatible with .zar files\n", .{});
            return error.IncompatibleFlags;
        }
        // ...
        const main_file_handle = file.?;

        // 1. Determine ZAR directory (relative or absolute)
        const parent_path = std.fs.path.dirname(filename) orelse ".";
        var parent_dir = try std.fs.cwd().openDir(parent_path, .{});

        // 2. Create hidden temp directory .zeus_tmp_<timestamp>
        const timestamp = std.time.nanoTimestamp();
        const tmp_name = try std.fmt.bufPrint(&tmp_name_buf, ".zeus_tmp_{}", .{timestamp});

        var tmp_dir = try parent_dir.makeOpenPath(tmp_name, .{});

        // 3. Configure FS Root and Cleanup
        fs_root = tmp_dir;
        fs_root_needs_close = true;

        cleanup_parent = parent_dir;
        cleanup_path = tmp_name;

        // 4. Extract ZAR
        try extractZar(main_file_handle, tmp_dir);

        // 5. Load main.zeus
        const main_file = try tmp_dir.openFile("main.zeus", .{});
        defer main_file.close();

        const main_len = try main_file.getEndPos();
        end_of_main = main_len;
        if (main_len > memory_size) {
            std.debug.print("Error: main.zeus size {} exceeds allocated memory {}\n", .{ main_len, memory_size });
            return error.MainTooLarge;
        }

        const read_n = try main_file.readAll(memory);
        if (read_n != main_len) {
            std.debug.print("Error: Failed to read main.zeus\n", .{});
            return error.MainReadError;
        }
    } else {
        if (file) |f| {
            const bytes_read = try f.readAll(memory);
            end_of_main = bytes_read;
            if (bytes_read != file_len) {
                std.debug.print("Error: Failed to read entire file\n", .{});
                return error.FileReadError;
            }
        } else if (assembly_code) |code| {
            @memcpy(memory[0..code.len], code);
            end_of_main = code.len;
        }
    }

    // Init FsCtx with configured root
    var fs_ctx = host.FsCtx{ .allocator = allocator, .table = std.AutoHashMap(bootstrap.FileHandle, std.fs.File).init(allocator), .next = 1, .root = fs_root };
    defer fs_ctx.table.deinit();

    var thread_ctx = host.ThreadCtx{ .allocator = allocator, .tasks = std.AutoHashMap(bootstrap.ThreadHandle, std.Thread).init(allocator), .next = 1 };
    defer thread_ctx.tasks.deinit();

    var net_ctx = host.NetCtx{ .allocator = allocator };
    var memory_ctx = host.MemoryCtx{ .allocator = allocator };

    var stdin_file = std.fs.File.stdin();
    var stdout_file = std.fs.File.stdout();
    var stderr_file = std.fs.File.stderr();

    const h = bootstrap.Host{
        .allocator = allocator,
        .args = program_args.items,
        .io = .{
            .stdin = .{ .read = host.stdioReaderRead, .ctx = &stdin_file },
            .stdout = .{ .write = host.stdioWriterWrite, .ctx = &stdout_file },
            .stderr = .{ .write = host.stdioWriterWrite, .ctx = &stderr_file },
        },
        .fs = .{ .open = host.fsOpen, .read = host.fsRead, .write = host.fsWrite, .close = host.fsClose, .ctx = &fs_ctx },
        .threading = .{ .spawn = host.threadSpawn, .join = host.threadJoin, .yield = host.threadYield, .ctx = &thread_ctx },
        .net = .{ .connect = host.netConnect, .listen = host.netListen, .poll = host.netPoll, .ctx = &net_ctx },
        .time = .{ .monotonic_ns = host.timeNow, .sleep_ns = host.timeSleep, .ctx = undefined },
        .memory = bootstrap.Memory{
            .alloc = host.memoryAlloc,
            .free = host.memoryFree,
            .protect = host.memoryProtect,
            .ctx = &memory_ctx,
        },
    };

    var vm = ZeusVM.vm.init(h, memory);
    if (use_jit) {
        vm.use_jit = true;
        vm.jit = try ZeusVM.vm.Jit.init(allocator, 1024 * 1024, h);
        vm.jit.?.threshold = jit_threshold;
    }
    defer if (vm.jit) |j| j.deinit(h);

    vm.pc = 0; // Execution starts at 0
    // Align end of main code to next 8-byte boundary
    vm.next_free_addr = (end_of_main + 7) & ~@as(usize, 7);

    try vm.runAsync();
}

fn parseSize(str: []const u8) !usize {
    if (str.len == 0) return error.InvalidFormat;
    var unit: usize = 1;

    var end: usize = str.len;
    if (std.mem.endsWith(u8, str, "KB") or std.mem.endsWith(u8, str, "kb") or std.mem.endsWith(u8, str, "Kb")) {
        unit = 1024;
        end -= 2;
    } else if (std.mem.endsWith(u8, str, "MB") or std.mem.endsWith(u8, str, "mb") or std.mem.endsWith(u8, str, "Mb")) {
        unit = 1024 * 1024;
        end -= 2;
    } else if (std.mem.endsWith(u8, str, "GB") or std.mem.endsWith(u8, str, "gb") or std.mem.endsWith(u8, str, "Gb")) {
        unit = 1024 * 1024 * 1024;
        end -= 2;
    } else {
        const last = str[str.len - 1];
        if (last == 'K' or last == 'k') {
            unit = 1024;
            end -= 1;
        } else if (last == 'M' or last == 'm') {
            unit = 1024 * 1024;
            end -= 1;
        } else if (last == 'G' or last == 'g') {
            unit = 1024 * 1024 * 1024;
            end -= 1;
        }
    }

    const val = try std.fmt.parseInt(usize, str[0..end], 10);
    return val * unit;
}

fn extractZar(file: std.fs.File, dest_dir: std.fs.Dir) !void {
    // Reset file position
    try file.seekTo(0);

    var buf: [4096]u8 = undefined;
    var reader = file.reader(&buf);
    var zip = try std.zip.Iterator.init(&reader);

    var main_found = false;

    while (try zip.next()) |entry| {
        // Read filename
        const cd_header_size = 46;
        try reader.seekTo(entry.header_zip_offset + cd_header_size);

        var filename_buf: [256]u8 = undefined;
        const len = if (entry.filename_len > 256) 256 else entry.filename_len;
        const filename = filename_buf[0..len];
        try reader.interface.readSliceAll(filename);

        if (std.mem.eql(u8, filename, "main.zeus")) main_found = true;

        if (entry.compression_method != .store) {
            std.debug.print("Error: Encrypted code or compressed entries not supported (entry: {s})\n", .{filename});
            return error.UnsupportedCompression;
        }

        // Security check: Prevent directory traversal
        if (std.mem.indexOf(u8, filename, "..") != null) {
            std.debug.print("Error: Malicious path detected (entry: {s})\n", .{filename});
            return error.MaliciousPath;
        }

        // Handle directories
        if (filename[filename.len - 1] == '/') {
            try dest_dir.makePath(filename);
            continue;
        }

        // Ensure parent directory exists for files
        if (std.fs.path.dirname(filename)) |dirname| {
            try dest_dir.makePath(dirname);
        }

        // Extract content
        // 1. Read Local File Header
        try reader.seekTo(entry.file_offset + 26);
        var len_bytes: [4]u8 = undefined;
        try reader.interface.readSliceAll(&len_bytes);

        const local_filename_len = std.mem.readInt(u16, len_bytes[0..2], .little);
        const local_extra_len = std.mem.readInt(u16, len_bytes[2..4], .little);

        const data_start = entry.file_offset + 30 + local_filename_len + local_extra_len;
        try reader.seekTo(data_start);

        const out_file = try dest_dir.createFile(filename, .{});
        defer out_file.close();

        var remain = entry.uncompressed_size;
        var copy_buf: [4096]u8 = undefined;
        while (remain > 0) {
            const to_read = if (remain > 4096) 4096 else @as(usize, @intCast(remain));
            try reader.interface.readSliceAll(copy_buf[0..to_read]);
            try out_file.writeAll(copy_buf[0..to_read]);
            remain -= to_read;
        }
    }

    if (!main_found) {
        std.debug.print("Error: main.zeus not found in archive\n", .{});
        return error.InvalidArchive;
    }
}
