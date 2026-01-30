const std = @import("std");

/// =======================
/// Core Host Entry Point
/// =======================
pub const Host = struct {
    allocator: std.mem.Allocator,
    args: []const []const u8 = &[_][]const u8{},

    threading: ?Threading = null,
    io: IO,
    fs: ?Filesystem = null,
    net: ?Networking = null,
    time: ?Time = null,
    memory: ?Memory = null,
};

/// =======================
/// Threading
/// =======================
pub const ThreadHandle = usize;

pub const Threading = struct {
    spawn: *const fn (
        ctx: *anyopaque,
        entry: *const fn (*anyopaque) void,
        arg: *anyopaque,
    ) anyerror!ThreadHandle,

    join: *const fn (
        ctx: *anyopaque,
        handle: ThreadHandle,
    ) anyerror!void,

    yield: *const fn (
        ctx: *anyopaque,
    ) void,

    ctx: *anyopaque,
};

/// =======================
/// IO Primitives
/// =======================
pub const Reader = struct {
    read: *const fn (
        ctx: *anyopaque,
        buffer: []u8,
    ) anyerror!usize,

    ctx: *anyopaque,
};

pub const Writer = struct {
    write: *const fn (
        ctx: *anyopaque,
        buffer: []const u8,
    ) anyerror!usize,

    ctx: *anyopaque,
};

pub const IO = struct {
    stdin: ?Reader = null,
    stdout: ?Writer = null,
    stderr: ?Writer = null,
};

/// =======================
/// Filesystem
/// =======================
pub const FileHandle = usize;

pub const OpenFlags = struct {
    read: bool = false,
    write: bool = false,
    create: bool = false,
    truncate: bool = false,
};

pub const Filesystem = struct {
    open: *const fn (
        ctx: *anyopaque,
        path: []const u8,
        flags: OpenFlags,
    ) anyerror!FileHandle,

    read: *const fn (
        ctx: *anyopaque,
        handle: FileHandle,
        buffer: []u8,
    ) anyerror!usize,

    write: *const fn (
        ctx: *anyopaque,
        handle: FileHandle,
        buffer: []const u8,
    ) anyerror!usize,

    close: *const fn (
        ctx: *anyopaque,
        handle: FileHandle,
    ) void,

    ctx: *anyopaque,
};

/// =======================
/// Networking
/// =======================
pub const Endpoint = union(enum) {
    ip: struct {
        addr: [4]u8,
        port: u16,
    },
    ip6: struct {
        addr: [16]u8,
        port: u16,
    },
    _opaque: []const u8,
};

pub const Stream = struct {
    reader: Reader,
    writer: Writer,
};

pub const PollEvent = enum(u8) {
    none,
    readable,
    writable,
    closed,
};

pub const Listener = struct {
    accept: *const fn (
        ctx: *anyopaque,
    ) anyerror!Stream,

    ctx: *anyopaque,
};

pub const Networking = struct {
    connect: *const fn (
        ctx: *anyopaque,
        endpoint: Endpoint,
    ) anyerror!Stream,

    listen: *const fn (
        ctx: *anyopaque,
        endpoint: Endpoint,
    ) anyerror!Listener,

    poll: *const fn (
        ctx: *anyopaque,
        stream: *anyopaque,
    ) anyerror!PollEvent,

    ctx: *anyopaque,
};

/// =======================
/// Time
/// =======================
pub const Time = struct {
    monotonic_ns: *const fn (ctx: *anyopaque) u64,
    sleep_ns: *const fn (ctx: *anyopaque, ns: u64) anyerror!void,

    ctx: *anyopaque,
};

/// =======================
/// Memory Protection
/// =======================
pub const MemoryProt = enum {
    read,
    read_write,
    read_exec,
    read_write_exec,
};

pub const Memory = struct {
    alloc: *const fn (ctx: *anyopaque, size: usize, alignment: usize) anyerror![]u8,
    free: *const fn (ctx: *anyopaque, buffer: []u8) void,
    protect: *const fn (ctx: *anyopaque, buffer: []u8, prot: MemoryProt) anyerror!void,

    ctx: *anyopaque,
};
