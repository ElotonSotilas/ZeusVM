const std = @import("std");
const ZeusVM = @import("ZeusVM");
const bootstrap = ZeusVM.bootstrap;

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
