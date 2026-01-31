const std = @import("std");
const ZeusVM = @import("ZeusVM");
const bootstrap = ZeusVM.bootstrap;
const host = @import("host.zig");

const Color = struct {
    pub const reset = "\x1b[0m";
    pub const bold = "\x1b[1m";
    pub const dim = "\x1b[2m";
    pub const red = "\x1b[31m";
    pub const green = "\x1b[32m";
    pub const yellow = "\x1b[33m";
    pub const blue = "\x1b[34m";
    pub const magenta = "\x1b[35m";
    pub const cyan = "\x1b[36m";
};

fn printError(writer: anytype, comptime fmt: []const u8, args: anytype) void {
    writer.print(Color.bold ++ Color.red ++ "error" ++ Color.reset ++ Color.bold ++ ": " ++ Color.reset ++ fmt ++ "\n", args) catch {};
}

fn printInfo(writer: anytype, comptime fmt: []const u8, args: anytype) void {
    writer.print(Color.bold ++ Color.blue ++ "info" ++ Color.reset ++ Color.bold ++ ": " ++ Color.reset ++ fmt ++ "\n", args) catch {};
}

pub fn main() void {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    realMain(allocator) catch |err| {
        if (err == error.UsageHelp) return;
        std.process.exit(1);
    };
}

fn realMain(allocator: std.mem.Allocator) !void {
    // Create host configuration early
    const h = try host.makeConfig(allocator, std.fs.cwd());
    defer host.freeConfig(h);
    // Note: We are using std.fs.cwd() for the root of the host FS for now.

    var stdout_host = HostWriter{ .inner = h.io.stdout.? };
    const stdout = stdout_host.getWriter();
    var stderr_host = HostWriter{ .inner = h.io.stderr.? };
    const stderr = stderr_host.getWriter();

    var args = host.getCliArgs(allocator) catch |err| {
        printError(stderr, "Failed to get CLI arguments: {s}", .{@errorName(err)});
        return err;
    };
    defer {
        for (args.items) |arg| {
            allocator.free(arg);
        }
        args.deinit(allocator);
    }

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
    while (i < args.items.len) : (i += 1) {
        const arg = args.items[i];

        if (std.mem.eql(u8, arg, "-m") or std.mem.eql(u8, arg, "--mem")) {
            if (i + 1 >= args.items.len) {
                printError(stderr, "{s} requires a size argument", .{arg});
                return error.ArgumentsError;
            }
            memory_size = parseSize(args.items[i + 1]) catch {
                printError(stderr, "Invalid size format '{s}'", .{args.items[i + 1]});
                return error.ArgumentsError;
            };
            i += 1;
        } else if (std.mem.eql(u8, arg, "-o")) {
            if (i + 1 >= args.items.len) {
                printError(stderr, "-o requires a filename argument", .{});
                return error.ArgumentsError;
            }
            output_file = args.items[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--run")) {
            force_run = true;
        } else if (std.mem.eql(u8, arg, "--no-jit")) {
            use_jit = false;
        } else if (std.mem.eql(u8, arg, "--jit-threshold")) {
            if (i + 1 >= args.items.len) {
                printError(stderr, "--jit-threshold requires a value", .{});
                return error.ArgumentsError;
            }
            jit_threshold = std.fmt.parseInt(u32, args.items[i + 1], 10) catch {
                printError(stderr, "Invalid threshold '{s}'", .{args.items[i + 1]});
                return error.ArgumentsError;
            };
            i += 1;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            if (target_file == null) {
                printError(stderr, "Unknown flag '{s}'", .{arg});
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
        stdout.print(Color.bold ++ Color.green ++ "ZeusVM" ++ Color.reset ++ " - High Performance JIT Virtual Machine\n\n", .{}) catch {};
        stdout.print(Color.bold ++ "Usage:" ++ Color.reset ++ " {s} [flags] <file.zeus|.zar|.zs> [args...]\n\n", .{args.items[0]}) catch {};
        stdout.print(Color.bold ++ "Flags:\n" ++ Color.reset, .{}) catch {};
        stdout.print("  " ++ Color.cyan ++ "-m, --mem" ++ Color.reset ++ " " ++ Color.dim ++ "<size>" ++ Color.reset ++ "    Set VM memory size (default 1MB)\n", .{}) catch {};
        stdout.print("  " ++ Color.cyan ++ "-o" ++ Color.reset ++ " " ++ Color.dim ++ "<file>" ++ Color.reset ++ "           Output file for assembler\n", .{}) catch {};
        stdout.print("  " ++ Color.cyan ++ "--run" ++ Color.reset ++ "               Force execution (runs .zs after assembly)\n", .{}) catch {};
        stdout.print("  " ++ Color.cyan ++ "--no-jit" ++ Color.reset ++ "            Disable JIT compilation\n", .{}) catch {};
        stdout.print("  " ++ Color.cyan ++ "--jit-threshold" ++ Color.reset ++ " " ++ Color.dim ++ "<n>" ++ Color.reset ++ " Set JIT hotness threshold (default 50)\n\n", .{}) catch {};
        stdout.print(Color.bold ++ "Examples:\n" ++ Color.reset, .{}) catch {};
        stdout.print("  {s} script.zs --run\n", .{args.items[0]}) catch {};
        stdout.print("  {s} app.zar -m 4MB\n", .{args.items[0]}) catch {};
        return error.UsageHelp;
    }

    const filename = target_file.?;

    const is_zs = std.mem.endsWith(u8, filename, ".zs");
    const mode_compile = is_zs and !force_run;

    // Handle Assembly
    var assembly_code: ?[]u8 = null;
    defer if (assembly_code) |code| allocator.free(code);

    if (is_zs) {
        const source = (blk: {
            const fs = h.fs.?;
            const fh = fs.open(fs.ctx, filename, .{ .read = true }) catch |err| {
                printError(stderr, "Opening assembly file '{s}': {}", .{ filename, err });
                return error.FileOpenError;
            };
            defer fs.close(fs.ctx, fh);
            const size = fs.getSize(fs.ctx, fh) catch |err| {
                printError(stderr, "Getting size of assembly file '{s}': {}", .{ filename, err });
                return error.FileOpenError;
            };
            const buf = try allocator.alloc(u8, size);
            const read = fs.read(fs.ctx, fh, buf) catch |err| {
                printError(stderr, "Reading assembly file '{s}': {}", .{ filename, err });
                allocator.free(buf);
                return error.FileReadError;
            };
            if (read != size) {
                printError(stderr, "Partial read of assembly file '{s}'", .{filename});
                allocator.free(buf);
                return error.FileReadError;
            }
            break :blk buf;
        });
        defer allocator.free(source);

        var assem = ZeusVM.assembler.Assembler.init(allocator, source);
        defer assem.deinit();

        assembly_code = assem.assemble() catch |err| {
            printError(stderr, "Assembling file '{s}': {}", .{ filename, err });
            return error.AssemblyError;
        };

        if (mode_compile) {
            const out_name = output_file orelse try std.fmt.allocPrint(allocator, "{s}.zeus", .{std.fs.path.stem(filename)});
            defer if (output_file == null) allocator.free(out_name);

            const fs = h.fs.?;
            const fh = try fs.open(fs.ctx, out_name, .{ .write = true, .create = true, .truncate = true });
            defer fs.close(fs.ctx, fh);

            _ = try fs.write(fs.ctx, fh, assembly_code.?);
            stdout.print(Color.bold ++ Color.green ++ "Success" ++ Color.reset ++ ": Assembled {s} -> {s} (" ++ Color.cyan ++ "{}" ++ Color.reset ++ " bytes)\n", .{ filename, out_name, assembly_code.?.len }) catch {};
            return;
        }
    }

    const fs = h.fs.?;
    const file_handle: ?bootstrap.FileHandle = if (assembly_code == null) (fs.open(fs.ctx, filename, .{ .read = true }) catch |err| {
        printError(stderr, "Opening file '{s}': {}", .{ filename, err });
        return error.FileOpenError;
    }) else null;
    defer if (file_handle) |fh| fs.close(fs.ctx, fh);

    const file_len = if (file_handle) |fh| try fs.getSize(fs.ctx, fh) else if (assembly_code) |code| code.len else 0;
    if (file_len > memory_size and !std.mem.endsWith(u8, filename, ".zar")) {
        printError(stderr, "File larger than memory size (" ++ Color.cyan ++ "{}" ++ Color.reset ++ " > " ++ Color.cyan ++ "{}" ++ Color.reset ++ ")", .{ file_len, memory_size });
        return error.MemoryTooSmall;
    }

    // Allocate VM memory
    const memory = try allocator.alloc(u8, memory_size);
    defer allocator.free(memory);
    @memset(memory, 0);

    // Load Content
    var end_of_main: u64 = 0;
    var tmp_name_buf: [64]u8 = undefined;

    // Filesystem Root Defer logic needs to stay to ensure cleanup
    var cleanup_path: ?[]const u8 = null;

    defer {
        if (cleanup_path) |path| {
            fs.deleteTree(fs.ctx, path) catch {};
            allocator.free(path);
        }
    }

    if (std.mem.endsWith(u8, filename, ".zar")) {
        if (is_zs) {
            printError(stderr, "Assembler is not compatible with .zar files", .{});
            return error.IncompatibleFlags;
        }

        const main_file_handle = file_handle.?;

        // 2. Create hidden temp directory .zeus_tmp_<timestamp>
        const timestamp = std.time.nanoTimestamp();
        const tmp_name = try std.fmt.bufPrint(&tmp_name_buf, ".zeus_tmp_{}", .{timestamp});

        try fs.makePath(fs.ctx, tmp_name);
        cleanup_path = try allocator.dupe(u8, tmp_name);

        // 4. Extract ZAR
        try extractZar(h, main_file_handle, tmp_name);

        // 5. Load main.zeus
        const main_zeus_path = try std.fs.path.join(allocator, &[_][]const u8{ tmp_name, "main.zeus" });
        defer allocator.free(main_zeus_path);

        const main_fh = try fs.open(fs.ctx, main_zeus_path, .{ .read = true });
        defer fs.close(fs.ctx, main_fh);

        const main_len = try fs.getSize(fs.ctx, main_fh);
        end_of_main = main_len;
        if (main_len > memory_size) {
            printError(stderr, "main.zeus size " ++ Color.cyan ++ "{}" ++ Color.reset ++ " exceeds allocated memory " ++ Color.cyan ++ "{}" ++ Color.reset, .{ main_len, memory_size });
            return error.MainTooLarge;
        }

        const read_n = try fs.read(fs.ctx, main_fh, memory);
        if (read_n != main_len) {
            printError(stderr, "Failed to read main.zeus", .{});
            return error.MainReadError;
        }
    } else {
        if (file_handle) |fh| {
            const bytes_read = try fs.read(fs.ctx, fh, memory);
            end_of_main = bytes_read;
            if (bytes_read != file_len) {
                printError(stderr, "Failed to read entire file", .{});
                return error.FileReadError;
            }
        } else if (assembly_code) |code| {
            @memcpy(memory[0..code.len], code);
            end_of_main = code.len;
        }
    }

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

const HostWriter = struct {
    inner: bootstrap.Writer,
    pub const Error = anyerror;
    pub fn write(self: HostWriter, bytes: []const u8) Error!usize {
        return self.inner.write(self.inner.ctx, bytes);
    }
    pub fn getWriter(self: HostWriter) std.io.GenericWriter(HostWriter, Error, write) {
        return .{ .context = self };
    }
};

const HostSeekableReader = struct {
    fs: bootstrap.Filesystem,
    handle: bootstrap.FileHandle,
    pos: u64 = 0,

    pub const Error = anyerror;
    pub fn read(self: *HostSeekableReader, buffer: []u8) Error!usize {
        const n = try self.fs.read(self.fs.ctx, self.handle, buffer);
        self.pos += n;
        return n;
    }
    pub fn seekTo(self: *HostSeekableReader, pos: u64) Error!void {
        try self.fs.seekTo(self.fs.ctx, self.handle, pos);
        self.pos = pos;
    }
    pub fn seekBy(self: *HostSeekableReader, amt: i64) Error!void {
        const new_pos = if (amt >= 0) self.pos + @as(u64, @intCast(amt)) else self.pos - @as(u64, @intCast(-amt));
        try self.seekTo(new_pos);
    }
    pub fn getPos(self: *HostSeekableReader) Error!u64 {
        return self.pos;
    }
    pub fn getEndPos(self: *HostSeekableReader) Error!u64 {
        return self.fs.getSize(self.fs.ctx, self.handle);
    }

    pub fn reader(self: *HostSeekableReader) std.io.Reader(*HostSeekableReader, Error, read) {
        return .{ .context = self };
    }
    pub fn seekableStream(self: *HostSeekableReader) std.io.SeekableStream(*HostSeekableReader, Error, Error, seekTo, seekBy, getPos, getEndPos) {
        return .{ .context = self };
    }
};

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

fn extractZar(h: bootstrap.Host, file_handle: bootstrap.FileHandle, dest_dir_path: []const u8) !void {
    const fs = h.fs.?;
    const allocator = h.allocator;
    var stderr_host = HostWriter{ .inner = h.io.stderr.? };
    const stderr = stderr_host.getWriter();

    const file_size = try fs.getSize(fs.ctx, file_handle);

    // 1. Find the End of Central Directory Record (EOCD)
    // It's at the end of the file. Minimum size is 22 bytes.
    if (file_size < 22) return error.InvalidArchive;

    var eocd_buf: [22]u8 = undefined;
    try fs.seekTo(fs.ctx, file_handle, file_size - 22);
    _ = try fs.read(fs.ctx, file_handle, &eocd_buf);

    if (!std.mem.eql(u8, eocd_buf[0..4], &[_]u8{ 'P', 'K', 5, 6 })) {
        // Might have a comment, search backwards? For ZeusVM we assume no comment.
        return error.InvalidArchiveNoCommentSupported;
    }

    const cd_entries = std.mem.readInt(u16, eocd_buf[10..12], .little);
    // const cd_size = std.mem.readInt(u32, eocd_buf[12..16], .little);
    const cd_offset = std.mem.readInt(u32, eocd_buf[16..20], .little);

    // 2. Iterate over Central Directory
    try fs.seekTo(fs.ctx, file_handle, cd_offset);

    var main_found = false;
    var entry_idx: u16 = 0;
    while (entry_idx < cd_entries) : (entry_idx += 1) {
        var cd_header: [46]u8 = undefined;
        _ = try fs.read(fs.ctx, file_handle, &cd_header);

        if (!std.mem.eql(u8, cd_header[0..4], &[_]u8{ 'P', 'K', 1, 2 })) return error.InvalidCentralDirectory;

        const compression = std.mem.readInt(u16, cd_header[10..12], .little);
        const uncompressed_size = std.mem.readInt(u32, cd_header[24..28], .little);
        const filename_len = std.mem.readInt(u16, cd_header[28..30], .little);
        const extra_len = std.mem.readInt(u16, cd_header[30..32], .little);
        const comment_len = std.mem.readInt(u16, cd_header[32..34], .little);
        const local_header_offset = std.mem.readInt(u32, cd_header[42..46], .little);

        const filename = try allocator.alloc(u8, filename_len);
        defer allocator.free(filename);
        _ = try fs.read(fs.ctx, file_handle, filename);

        // Skip extra and comment
        try fs.seekTo(fs.ctx, file_handle, try fs.getSize(fs.ctx, file_handle) - (file_size - (cd_offset + 46 + filename_len + extra_len + comment_len)));
        // Wait, the seek logic is simpler:
        const current_pos = cd_offset + 46 + filename_len + extra_len + comment_len;
        // i'll just seek relative or use a tracker.
        // Let's use a tracker for next entry.
        const next_entry_offset = current_pos;

        if (std.mem.eql(u8, filename, "main.zeus")) main_found = true;

        if (compression != 0) {
            printError(stderr, "Compressed entries not supported (entry: " ++ Color.yellow ++ "{s}" ++ Color.reset ++ ")", .{filename});
            return error.UnsupportedCompression;
        }

        if (std.mem.indexOf(u8, filename, "..") != null) {
            printError(stderr, "Malicious path detected (entry: " ++ Color.yellow ++ "{s}" ++ Color.reset ++ ")", .{filename});
            return error.MaliciousPath;
        }

        // 3. Read Local File Header and extract
        const saved_pos = next_entry_offset;
        try fs.seekTo(fs.ctx, file_handle, local_header_offset);

        var local_header: [30]u8 = undefined;
        _ = try fs.read(fs.ctx, file_handle, &local_header);

        if (!std.mem.eql(u8, local_header[0..4], &[_]u8{ 'P', 'K', 3, 4 })) return error.InvalidLocalHeader;

        const l_filename_len = std.mem.readInt(u16, local_header[26..28], .little);
        const l_extra_len = std.mem.readInt(u16, local_header[28..30], .little);

        const data_offset = local_header_offset + 30 + l_filename_len + l_extra_len;
        try fs.seekTo(fs.ctx, file_handle, data_offset);

        const full_path = try std.fs.path.join(allocator, &[_][]const u8{ dest_dir_path, filename });
        defer allocator.free(full_path);

        if (filename[filename.len - 1] == '/') {
            try fs.makePath(fs.ctx, full_path);
        } else {
            if (std.fs.path.dirname(full_path)) |dirname| {
                try fs.makePath(fs.ctx, dirname);
            }
            const out_fh = try fs.open(fs.ctx, full_path, .{ .write = true, .create = true, .truncate = true });
            defer fs.close(fs.ctx, out_fh);

            var remain = uncompressed_size;
            var copy_buf: [4096]u8 = undefined;
            while (remain > 0) {
                const to_read = if (remain > 4096) 4096 else @as(usize, @intCast(remain));
                _ = try fs.read(fs.ctx, file_handle, copy_buf[0..to_read]);
                _ = try fs.write(fs.ctx, out_fh, copy_buf[0..to_read]);
                remain -= @intCast(to_read);
            }
        }

        try fs.seekTo(fs.ctx, file_handle, saved_pos);
    }

    if (!main_found) {
        printError(stderr, "main.zeus not found in archive", .{});
        return error.InvalidArchive;
    }
}
