const std = @import("std");
const ZeusVM = @import("ZeusVM");
const bootstrap = ZeusVM.bootstrap;

const c = @cImport({
    @cInclude("ffi.h");
});

/// =======================
/// CLI Arguments
/// =======================
/// Get command-line arguments as an ArrayList
/// Caller is responsible for calling deinit() on the returned ArrayList
pub fn getCliArgs(allocator: std.mem.Allocator) !std.ArrayList([]const u8) {
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var args_list = std.ArrayList([]const u8).empty;
    errdefer args_list.deinit(allocator);

    for (args) |arg| {
        try args_list.append(allocator, try allocator.dupe(u8, arg));
    }

    return args_list;
}

/// =======================
/// Std IO Adapters (sync)
/// =======================
pub fn stdioReaderRead(ctx: *anyopaque, buffer: []u8) !usize {
    const file: *std.fs.File = @ptrCast(@alignCast(ctx));
    return file.read(buffer);
}
pub fn stdioWriterWrite(ctx: *anyopaque, buffer: []const u8) !usize {
    const file: *std.fs.File = @ptrCast(@alignCast(ctx));
    return file.write(buffer);
}

/// =======================
/// Filesystem Adapter (sync)
/// =======================
pub const FsCtx = struct {
    allocator: std.mem.Allocator,
    table: std.AutoHashMap(bootstrap.FileHandle, std.fs.File),
    next: bootstrap.FileHandle,
    root: std.fs.Dir,
};

pub fn fsOpen(ctx: *anyopaque, path: []const u8, flags: bootstrap.OpenFlags) !bootstrap.FileHandle {
    const fs: *FsCtx = @ptrCast(@alignCast(ctx));

    if (flags.create) {
        // Use createFile
        const file = try fs.root.createFile(path, .{ .truncate = flags.truncate, .read = flags.read });
        const handle = fs.next;
        fs.next += 1;
        try fs.table.put(handle, file);
        return handle;
    } else {

        // Use openFile
        var mode: std.fs.File.OpenMode = .read_only;
        if (flags.write and flags.read) {
            mode = .read_write;
        } else if (flags.write) {
            mode = .write_only;
        }

        const file = try fs.root.openFile(path, .{ .mode = mode });
        const handle = fs.next;
        fs.next += 1;
        try fs.table.put(handle, file);
        return handle;
    }
}
pub fn fsRead(ctx: *anyopaque, handle: bootstrap.FileHandle, buffer: []u8) !usize {
    const fs: *FsCtx = @ptrCast(@alignCast(ctx));
    return fs.table.get(handle).?.read(buffer);
}
pub fn fsWrite(ctx: *anyopaque, handle: bootstrap.FileHandle, buffer: []const u8) !usize {
    const fs: *FsCtx = @ptrCast(@alignCast(ctx));
    return fs.table.get(handle).?.write(buffer);
}
pub fn fsClose(ctx: *anyopaque, handle: bootstrap.FileHandle) void {
    const fs: *FsCtx = @ptrCast(@alignCast(ctx));
    if (fs.table.fetchRemove(handle)) |entry| {
        entry.value.close();
    }
}
pub fn fsGetSize(ctx: *anyopaque, handle: bootstrap.FileHandle) !u64 {
    const fs: *FsCtx = @ptrCast(@alignCast(ctx));
    const file = fs.table.get(handle) orelse return error.InvalidHandle;
    return file.getEndPos();
}
pub fn fsSeekTo(ctx: *anyopaque, handle: bootstrap.FileHandle, pos: u64) !void {
    const fs: *FsCtx = @ptrCast(@alignCast(ctx));
    const file = fs.table.get(handle) orelse return error.InvalidHandle;
    try file.seekTo(pos);
}
pub fn fsMakePath(ctx: *anyopaque, path: []const u8) !void {
    const fs: *FsCtx = @ptrCast(@alignCast(ctx));
    try fs.root.makePath(path);
}
pub fn fsDeleteTree(ctx: *anyopaque, path: []const u8) !void {
    const fs: *FsCtx = @ptrCast(@alignCast(ctx));
    try fs.root.deleteTree(path);
}

/// =======================
/// Async Threading Adapter
/// =======================
pub const ThreadCtx = struct {
    allocator: std.mem.Allocator,
    tasks: std.AutoHashMap(bootstrap.ThreadHandle, std.Thread),
    next: bootstrap.ThreadHandle,
};

const ThreadArgs = struct {
    entry: *const fn (*anyopaque) void,
    arg: *anyopaque,
};

fn threadEntry(args: ThreadArgs) void {
    args.entry(args.arg);
}

pub fn threadSpawn(ctx: *anyopaque, entry: *const fn (*anyopaque) void, arg: *anyopaque) !bootstrap.ThreadHandle {
    const tctx: *ThreadCtx = @ptrCast(@alignCast(ctx));

    const targs = ThreadArgs{ .entry = entry, .arg = arg };
    const task = try std.Thread.spawn(.{}, threadEntry, .{targs});
    const handle = tctx.next;
    tctx.next += 1;
    try tctx.tasks.put(handle, task);
    return handle;
}

pub fn threadJoin(ctx: *anyopaque, handle: bootstrap.ThreadHandle) !void {
    const tctx: *ThreadCtx = @ptrCast(@alignCast(ctx));
    const entry = tctx.tasks.get(handle) orelse return error.InvalidThreadHandle;
    entry.join();
    _ = tctx.tasks.fetchRemove(handle);
}

pub fn threadYield(ctx: *anyopaque) void {
    _ = ctx;
    std.Thread.yield() catch {};
}

/// =======================
/// Async Networking Adapter
/// =======================
pub const NetCtx = struct {
    allocator: std.mem.Allocator,
};

pub fn netConnect(ctx: *anyopaque, endpoint: bootstrap.Endpoint) !bootstrap.Stream {
    const net: *NetCtx = @ptrCast(@alignCast(ctx));
    switch (endpoint) {
        .ip => |ip| {
            const conn = try std.net.tcpConnectToAddress(std.net.Address.initIp4(ip.addr, ip.port));
            const conn_ptr = try net.allocator.create(std.net.Stream);
            conn_ptr.* = conn;
            return bootstrap.Stream{
                .reader = .{ .read = stdioReaderRead, .ctx = conn_ptr },
                .writer = .{ .write = stdioWriterWrite, .ctx = conn_ptr },
            };
        },
        else => return error.UnsupportedEndpoint,
    }
}

pub fn netPoll(ctx: *anyopaque, stream: *anyopaque) !bootstrap.PollEvent {
    _ = ctx;
    _ = stream;
    return .readable;
}
pub fn netListen(ctx: *anyopaque, endpoint: bootstrap.Endpoint) !bootstrap.Listener {
    const net: *NetCtx = @ptrCast(@alignCast(ctx));
    _ = net;
    switch (endpoint) {
        .ip => |ip| {
            var server = try std.net.Address.initIp4(ip.addr, ip.port).listen(.{});
            return bootstrap.Listener{
                .accept = struct {
                    fn accept(ctx2: *anyopaque) !bootstrap.Stream {
                        const srv: *std.net.Server = @ptrCast(@alignCast(ctx2));
                        const conn = try srv.accept();
                        const conn_ptr = try std.heap.page_allocator.create(std.net.Server.Connection);
                        conn_ptr.* = conn;
                        return bootstrap.Stream{
                            .reader = .{ .read = stdioReaderRead, .ctx = conn_ptr },
                            .writer = .{ .write = stdioWriterWrite, .ctx = conn_ptr },
                        };
                    }
                }.accept,
                .ctx = &server,
            };
        },
        else => return error.UnsupportedEndpoint,
    }
}

/// =======================
/// Async Time Adapter
/// =======================
pub fn timeNow(ctx: *anyopaque) u64 {
    _ = ctx;
    return @intCast(std.time.nanoTimestamp());
}

pub const SleepState = struct {
    wake_ns: u64,
};

pub fn timeSleep(ctx: *anyopaque, ns: u64) !void {
    const now = std.time.nanoTimestamp();
    const wake_ns = now + ns;

    // Store sleep state in the context
    const state: *SleepState = @ptrCast(@alignCast(ctx));
    state.wake_ns = @intCast(wake_ns);

    if (std.time.nanoTimestamp() < state.wake_ns) {
        return error.NotReady; // tell the VM to retry later
    }
}

/// =======================
/// Memory Adapter (JIT)
/// =======================
pub const MemoryCtx = struct {
    allocator: std.mem.Allocator,
};

pub fn memoryAlloc(ctx: *anyopaque, size: usize, alignment: usize) ![]u8 {
    const m: *MemoryCtx = @ptrCast(@alignCast(ctx));
    const align_log2: u8 = @intCast(std.math.log2(alignment));
    const ptr = m.allocator.vtable.alloc(m.allocator.ptr, size, @enumFromInt(align_log2), @returnAddress()) orelse return error.OutOfMemory;
    return ptr[0..size];
}

pub fn memoryFree(ctx: *anyopaque, buffer: []u8) void {
    const m: *MemoryCtx = @ptrCast(@alignCast(ctx));
    m.allocator.free(buffer);
}

pub fn memoryProtect(ctx: *anyopaque, buffer: []u8, prot: bootstrap.MemoryProt) !void {
    _ = ctx;
    const p: u32 = switch (prot) {
        .read => @as(u32, @intCast(std.posix.PROT.READ)),
        .read_write => @as(u32, @intCast(std.posix.PROT.READ | std.posix.PROT.WRITE)),
        .read_exec => @as(u32, @intCast(std.posix.PROT.READ | std.posix.PROT.EXEC)),
        .read_write_exec => @as(u32, @intCast(std.posix.PROT.READ | std.posix.PROT.WRITE | std.posix.PROT.EXEC)),
    };
    try std.posix.mprotect(@alignCast(buffer), p);
}

/// =======================
/// Dynamic Library Adapter
/// =======================
/// Configuration for library loading
pub const LibraryConfig = struct {
    paths: []const []const u8,
    extensions: []const []const u8,
};

/// Create library configuration based on environment and platform
pub fn makeLibraryConfig(allocator: std.mem.Allocator) !LibraryConfig {
    // Get library search paths from environment or use defaults
    const paths = blk: {
        // Try to get LD_LIBRARY_PATH from environment
        if (std.process.getEnvVarOwned(allocator, "LD_LIBRARY_PATH")) |env_path| {
            // Split by ':' and create array
            var path_list = std.ArrayList([]const u8).empty;
            path_list.deinit(allocator);
            path_list = std.ArrayList([]const u8).empty;
            var iter = std.mem.splitScalar(u8, env_path, ':');
            while (iter.next()) |path| {
                try path_list.append(allocator, try allocator.dupe(u8, path));
            }
            allocator.free(env_path);
            break :blk try path_list.toOwnedSlice(allocator);
        } else |_| {
            // Use default system library paths
            const default_paths = &[_][]const u8{
                "", // System default (uses ld cache)
                "/usr/lib/",
                "/usr/local/lib/",
                "/lib/",
                "/lib64/",
                "/usr/lib64/",
                "/usr/lib/x86_64-linux-gnu/", // Debian/Ubuntu x86_64
                "/usr/lib/aarch64-linux-gnu/", // Debian/Ubuntu ARM64
            };
            break :blk try allocator.dupe([]const u8, default_paths);
        }
    };

    // Get platform-specific library extensions
    const extensions = comptime blk: {
        if (@import("builtin").os.tag == .windows) {
            break :blk &[_][]const u8{".dll"};
        } else if (@import("builtin").os.tag == .macos) {
            break :blk &[_][]const u8{ ".dylib", ".so" };
        } else {
            // Linux, BSD, etc.
            break :blk &[_][]const u8{".so"};
        }
    };

    return LibraryConfig{
        .paths = paths,
        .extensions = extensions,
    };
}

/// Free library configuration
pub fn freeLibraryConfig(allocator: std.mem.Allocator, config: LibraryConfig) void {
    for (config.paths) |path| {
        // Only free if not from default_paths (which are compile-time constants)
        if (path.ptr != "".ptr and
            path.ptr != "/usr/lib/".ptr and
            path.ptr != "/usr/local/lib/".ptr and
            path.ptr != "/lib/".ptr and
            path.ptr != "/lib64/".ptr and
            path.ptr != "/usr/lib64/".ptr and
            path.ptr != "/usr/lib/x86_64-linux-gnu/".ptr and
            path.ptr != "/usr/lib/aarch64-linux-gnu/".ptr)
        {
            allocator.free(path);
        }
    }
    allocator.free(config.paths);
}

pub const LibraryCtx = struct {
    allocator: std.mem.Allocator,
    libs: std.AutoHashMap(bootstrap.LibraryHandle, std.DynLib),
    next: bootstrap.LibraryHandle,
    library_paths: []const []const u8, // Host-provided library search paths
    library_extensions: []const []const u8, // Host-provided library extensions
    io_ctx: *IoCtx,
};

pub fn libOpen(ctx: *anyopaque, path: []const u8) !bootstrap.LibraryHandle {
    const self: *LibraryCtx = @ptrCast(@alignCast(ctx));

    // Try to open the library with smart search using host-provided paths and extensions
    const lib = try openLibrarySmart(self.allocator, path, self.library_paths, self.library_extensions);

    const handle = self.next;
    self.next += 1;
    try self.libs.put(handle, lib);
    return handle;
}

/// Find the best matching library in a directory with optional version numbers
/// Prioritizes versioned libraries (e.g., libc.so.6) over non-versioned (libc.so)
fn findBestLibraryMatch(allocator: std.mem.Allocator, dir_path: []const u8, base_name: []const u8, extension: []const u8) ?[]const u8 {
    // Open directory
    var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch return null;
    defer dir.close();

    // Track best match
    var best_match: ?[]const u8 = null;
    var best_has_version = false;

    // Expected patterns:
    // - base_name + extension (e.g., "libc.so")
    // - base_name + extension + ".N" (e.g., "libc.so.6")
    // - base_name + extension + ".N.N" (e.g., "libssl.so.1.1")
    // - base_name + extension + ".N.N.N" (e.g., "libcrypto.so.1.1.0")

    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind != .file) continue;

        const name = entry.name;

        // Must start with base_name + extension
        const prefix = allocator.alloc(u8, base_name.len + extension.len) catch continue;
        defer allocator.free(prefix);
        @memcpy(prefix[0..base_name.len], base_name);
        @memcpy(prefix[base_name.len..], extension);

        if (!std.mem.startsWith(u8, name, prefix)) continue;

        // Check what comes after the prefix
        const suffix = name[prefix.len..];

        if (suffix.len == 0) {
            // Exact match: base_name + extension (no version)
            if (!best_has_version) {
                if (best_match) |old| allocator.free(old);
                best_match = allocator.dupe(u8, name) catch continue;
            }
        } else if (suffix[0] == '.') {
            // Has additional dot - check if it's a version number
            const version_part = suffix[1..];
            if (isVersionString(version_part)) {
                // This is a versioned library - prioritize it!
                if (best_match) |old| allocator.free(old);
                best_match = allocator.dupe(u8, name) catch continue;
                best_has_version = true;
            }
        }
    }

    return best_match;
}

/// Check if a string looks like a version number (e.g., "6", "1.1", "1.1.0")
fn isVersionString(s: []const u8) bool {
    if (s.len == 0) return false;

    var has_digit = false;
    for (s) |ch| {
        if (ch >= '0' and ch <= '9') {
            has_digit = true;
        } else if (ch != '.') {
            return false; // Invalid character
        }
    }

    return has_digit;
}

/// Smart library opener that searches provided paths and uses regex for versioned libraries
fn openLibrarySmart(allocator: std.mem.Allocator, name: []const u8, library_paths: []const []const u8, extensions: []const []const u8) !std.DynLib {
    // If it's already a path (contains / or \), try to open directly
    if (std.mem.indexOfAny(u8, name, "/\\")) |_| {
        return std.DynLib.open(name) catch return error.LibraryNotFound;
    }

    // Try original name first - uses system's dynamic linker cache
    if (std.DynLib.open(name)) |lib| {
        return lib;
    } else |_| {}

    // Check if name already has "lib" prefix
    const has_lib_prefix = std.mem.startsWith(u8, name, "lib");

    // Try different combinations using host-provided library paths
    for (library_paths) |search_path| {
        // Try with lib prefix
        const lib_name = if (has_lib_prefix) name else try std.fmt.allocPrint(allocator, "lib{s}", .{name});
        defer if (!has_lib_prefix) allocator.free(lib_name);

        for (extensions) |ext| {
            // Use directory scanning to find best matching library (with version prioritization)
            if (findBestLibraryMatch(allocator, search_path, lib_name, ext)) |filename| {
                defer allocator.free(filename);

                const full_path = try std.fmt.allocPrint(
                    allocator,
                    "{s}{s}",
                    .{ search_path, filename },
                );
                defer allocator.free(full_path);

                if (std.DynLib.open(full_path)) |lib| {
                    return lib;
                } else |_| {}
            }
        }

        // Also try without lib prefix (user might have specified full name)
        if (!has_lib_prefix) {
            for (extensions) |ext| {
                // Use directory scanning to find best matching library
                if (findBestLibraryMatch(allocator, search_path, name, ext)) |filename| {
                    defer allocator.free(filename);

                    const full_path = try std.fmt.allocPrint(
                        allocator,
                        "{s}{s}",
                        .{ search_path, filename },
                    );
                    defer allocator.free(full_path);

                    if (std.DynLib.open(full_path)) |lib| {
                        return lib;
                    } else |_| {}
                }
            }
        }
    }

    return error.LibraryNotFound;
}

pub fn libClose(ctx: *anyopaque, handle: bootstrap.LibraryHandle) void {
    const self: *LibraryCtx = @ptrCast(@alignCast(ctx));
    if (self.libs.fetchRemove(handle)) |entry| {
        var lib = entry.value;
        lib.close();
    }
}

pub fn libLookup(ctx: *anyopaque, handle: bootstrap.LibraryHandle, symbol: []const u8) !usize {
    const self: *LibraryCtx = @ptrCast(@alignCast(ctx));
    const lib = self.libs.getPtr(handle) orelse return error.InvalidHandle;
    // We need to null-terminate the symbol as DynLib expects 0-terminated c-string usually or a slice, but let's be safe.
    // Actually std.DynLib.lookup takes a slice.

    // However, if the symbol is not found, it returns null.
    // Address 0 is typically invalid for a function, so we can check on that too if needed, but the option type handles it.
    // Create null-terminated copy for std.DynLib.lookup
    const symbol_z = try self.allocator.dupeZ(u8, symbol);
    defer self.allocator.free(symbol_z);

    if (lib.lookup(*anyopaque, symbol_z)) |sym| {
        return @intFromPtr(sym);
    }
    return error.SymbolNotFound;
}

pub fn libCall(ctx: *anyopaque, address: usize, args: [*]const u64, type_mask: u64, count: usize, vm_memory: [*]u8, vm_memory_size: usize) u64 {
    _ = ctx;

    // Type encoding: 2 bits per argument
    // 00 = uint64 (integer)
    // 01 = double (float)
    // 10 = pointer (needs translation)
    // 11 = reserved

    // Prepare argument types and values for libffi
    var arg_types_buf: [32]*c.ffi_type = undefined;
    var arg_values_buf: [32]*anyopaque = undefined;
    var arg_storage_buf: [32]u64 = undefined;

    // Build argument type and value arrays
    var i: usize = 0;
    while (i < count) : (i += 1) {
        // Extract 2-bit type for this argument
        const type_bits = (type_mask >> @intCast(i * 2)) & 0x3;

        switch (type_bits) {
            0 => {
                // Integer (uint64)
                arg_types_buf[i] = &c.ffi_type_uint64;
                arg_storage_buf[i] = args[i];
                arg_values_buf[i] = @ptrCast(&arg_storage_buf[i]);
            },
            1 => {
                // Float (double)
                arg_types_buf[i] = &c.ffi_type_double;
                arg_storage_buf[i] = args[i];
                arg_values_buf[i] = @ptrCast(&arg_storage_buf[i]);
            },
            2 => {
                // Pointer - translate VM address to host pointer
                arg_types_buf[i] = &c.ffi_type_pointer;
                const vm_addr = args[i];

                // Check if address is within VM memory bounds
                if (vm_addr < vm_memory_size) {
                    // Valid VM address - translate to host pointer
                    const host_ptr = @intFromPtr(vm_memory + vm_addr);
                    arg_storage_buf[i] = host_ptr;
                } else {
                    // Invalid address - pass NULL
                    arg_storage_buf[i] = 0;
                }
                arg_values_buf[i] = @ptrCast(&arg_storage_buf[i]);
            },
            3 => {
                // Reserved - treat as uint64 for now
                arg_types_buf[i] = &c.ffi_type_uint64;
                arg_storage_buf[i] = args[i];
                arg_values_buf[i] = @ptrCast(&arg_storage_buf[i]);
            },
            else => unreachable,
        }
    }

    // Prepare the call interface
    var cif: c.ffi_cif = undefined;
    const status = c.ffi_prep_cif(
        &cif,
        c.FFI_DEFAULT_ABI,
        @intCast(count),
        &c.ffi_type_uint64,
        @ptrCast(&arg_types_buf),
    );

    if (status != c.FFI_OK) {
        std.debug.print("DEBUG libCall: ffi_prep_cif failed with status={}\n", .{status});
        // FFI preparation failed, return 0 as error indicator
        return 0;
    }

    // Call the function
    var result: u64 = 0;
    c.ffi_call(&cif, @ptrFromInt(address), &result, @ptrCast(&arg_values_buf));

    return result;
}

/// =======================
/// Host Configuration
/// =======================
/// Complete host configuration including all contexts
/// Create a complete host configuration
pub fn makeConfig(allocator: std.mem.Allocator, fs_root: std.fs.Dir) !bootstrap.Host {
    // Initialize filesystem context on the heap
    const fs_ctx = try allocator.create(FsCtx);
    errdefer allocator.destroy(fs_ctx);
    fs_ctx.* = FsCtx{
        .allocator = allocator,
        .table = std.AutoHashMap(bootstrap.FileHandle, std.fs.File).init(allocator),
        .next = 1,
        .root = fs_root,
    };

    // Initialize thread context on the heap
    const thread_ctx = try allocator.create(ThreadCtx);
    errdefer allocator.destroy(thread_ctx);
    thread_ctx.* = ThreadCtx{
        .allocator = allocator,
        .tasks = std.AutoHashMap(bootstrap.ThreadHandle, std.Thread).init(allocator),
        .next = 1,
    };

    // Initialize network context on the heap
    const net_ctx = try allocator.create(NetCtx);
    errdefer allocator.destroy(net_ctx);
    net_ctx.* = NetCtx{ .allocator = allocator };

    // Initialize memory context on the heap
    const memory_ctx = try allocator.create(MemoryCtx);
    errdefer allocator.destroy(memory_ctx);
    memory_ctx.* = MemoryCtx{ .allocator = allocator };

    // Get library configuration
    const library_config = try makeLibraryConfig(allocator);
    errdefer freeLibraryConfig(allocator, library_config);

    // Initialize library context on the heap
    const library_ctx = try allocator.create(LibraryCtx);
    errdefer allocator.destroy(library_ctx);

    // Initialize IO context on the heap to avoid stack pointers
    const io_ctx = try allocator.create(IoCtx);
    errdefer allocator.destroy(io_ctx);
    io_ctx.* = IoCtx{
        .stdin = std.fs.File.stdin(),
        .stdout = std.fs.File.stdout(),
        .stderr = std.fs.File.stderr(),
    };

    library_ctx.* = LibraryCtx{
        .allocator = allocator,
        .libs = std.AutoHashMap(bootstrap.LibraryHandle, std.DynLib).init(allocator),
        .next = 1,
        .library_paths = library_config.paths,
        .library_extensions = library_config.extensions,
        .io_ctx = io_ctx,
    };

    // Build the host configuration
    const host = bootstrap.Host{
        .allocator = allocator,
        .io = .{
            .stdin = .{ .read = stdioReaderRead, .ctx = &io_ctx.stdin },
            .stdout = .{ .write = stdioWriterWrite, .ctx = &io_ctx.stdout },
            .stderr = .{ .write = stdioWriterWrite, .ctx = &io_ctx.stderr },
        },
        .fs = .{
            .open = fsOpen,
            .read = fsRead,
            .write = fsWrite,
            .close = fsClose,
            .getSize = fsGetSize,
            .seekTo = fsSeekTo,
            .makePath = fsMakePath,
            .deleteTree = fsDeleteTree,
            .ctx = fs_ctx,
        },
        .threading = .{ .spawn = threadSpawn, .join = threadJoin, .yield = threadYield, .ctx = thread_ctx },
        .net = .{ .connect = netConnect, .listen = netListen, .poll = netPoll, .ctx = net_ctx },
        .time = .{ .monotonic_ns = timeNow, .sleep_ns = timeSleep, .ctx = undefined },
        .memory = bootstrap.Memory{
            .alloc = memoryAlloc,
            .free = memoryFree,
            .protect = memoryProtect,
            .ctx = memory_ctx,
        },
        .library = .{
            .open = libOpen,
            .close = libClose,
            .lookup = libLookup,
            .call = libCall,
            .ctx = library_ctx,
            .library_paths = library_config.paths,
            .library_extensions = library_config.extensions,
        },
    };

    return host;
}

pub fn freeConfig(h: bootstrap.Host) void {
    const allocator = h.allocator;

    // Library cleanup
    if (h.library) |lib| {
        const library_ctx: *LibraryCtx = @ptrCast(@alignCast(lib.ctx));
        library_ctx.libs.deinit();
        const config = LibraryConfig{
            .paths = library_ctx.library_paths,
            .extensions = library_ctx.library_extensions,
        };
        freeLibraryConfig(allocator, config);
        allocator.destroy(library_ctx.io_ctx);
        allocator.destroy(library_ctx);
    }

    // FS cleanup
    if (h.fs) |fs| {
        const fs_ctx: *FsCtx = @ptrCast(@alignCast(fs.ctx));
        fs_ctx.table.deinit();
        allocator.destroy(fs_ctx);
    }

    // Threading cleanup
    if (h.threading) |t| {
        const thread_ctx: *ThreadCtx = @ptrCast(@alignCast(t.ctx));
        thread_ctx.tasks.deinit();
        allocator.destroy(thread_ctx);
    }

    // Net cleanup
    if (h.net) |n| {
        const net_ctx: *NetCtx = @ptrCast(@alignCast(n.ctx));
        allocator.destroy(net_ctx);
    }

    // Memory cleanup
    if (h.memory) |m| {
        const memory_ctx: *MemoryCtx = @ptrCast(@alignCast(m.ctx));
        allocator.destroy(memory_ctx);
    }
}

pub const IoCtx = struct {
    stdin: std.fs.File,
    stdout: std.fs.File,
    stderr: std.fs.File,
};
