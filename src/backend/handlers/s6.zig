const std = @import("std");
const ZeusVM = @import("../../root.zig");
const VM = ZeusVM.vm.VM;

///==============================
/// Helpers
///==============================
pub const Endpoint = struct {
    ip: [16]u8, // IPv6 or IPv4-mapped
    port: u16,
};

fn rd(inst: u64) u8 {
    return @intCast((inst >> 48) & 0xFF);
}

fn rs1(inst: u64) u8 {
    return @intCast((inst >> 40) & 0xFF);
}

fn rs2(inst: u64) u8 {
    return @intCast((inst >> 32) & 0xFF);
}

fn imm32(inst: u64) u32 {
    return @intCast(inst & 0xffff_ffff);
}

fn slice64(memory: []u8, addr: usize) []u8 {
    return memory[addr .. addr + 8]; // always 64-bit access
}

fn slice_bytes(vm: *VM, addr: u64, len: usize) []u8 {
    const start: usize = @intCast(addr);
    std.debug.assert(start + len <= vm.memory.len);
    return vm.memory[start .. start + len];
}

///==============================
/// Networking
///==============================
pub fn net_open(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const endpoint_ptr_idx = rs1(inst);

    const ep_addr = vm.regs[endpoint_ptr_idx];
    const ep: *const Endpoint = @ptrCast(@alignCast(&vm.memory[@intCast(ep_addr)]));

    const ep_val = ZeusVM.bootstrap.Endpoint{ .ip6 = .{ .addr = ep.ip, .port = ep.port } };
    const stream_val = vm.host.net.?.connect(vm.host.net.?.ctx, ep_val) catch return error.NotReady;
    const stream_ptr = vm.host.allocator.create(ZeusVM.bootstrap.Stream) catch return error.NotReady;
    stream_ptr.* = stream_val;
    vm.regs[rd_idx] = @intFromPtr(stream_ptr);
}

pub fn net_close(vm: *VM, inst: u64) !void {
    const handle_idx = rs1(inst);
    const handle: *anyopaque = @ptrFromInt(vm.regs[handle_idx]);

    // assume host object has a close method
    _ = handle; // call user-provided close if necessary
    vm.regs[handle_idx] = 0; // invalidate handle in VM
}

pub fn net_send(vm: *VM, inst: u64) !void {
    const handle_idx = rs1(inst);
    const buf_ptr_idx = rs2(inst);
    const len: usize = @intCast(imm32(inst));

    const stream: *ZeusVM.bootstrap.Stream = @ptrFromInt(vm.regs[handle_idx]);
    const buf_addr = vm.regs[buf_ptr_idx];
    const slice = slice_bytes(vm, buf_addr, len);

    const writer = stream.writer;

    _ = writer.write(writer.ctx, slice) catch |err| {
        if (err == error.WouldBlock) return error.NotReady else return err;
    };
}

pub fn net_recv(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const handle_idx = rs1(inst);
    const buf_ptr_idx = rs2(inst);
    const len: usize = @intCast(imm32(inst));

    const stream: *ZeusVM.bootstrap.Stream = @ptrFromInt(vm.regs[handle_idx]);
    const buf = slice_bytes(vm, vm.regs[buf_ptr_idx], len);

    const n = stream.reader.read(stream.reader.ctx, buf) catch |err| {
        if (err == error.WouldBlock) return error.NotReady else return err;
    };
    vm.regs[rd_idx] = @intCast(n);
}

pub fn net_poll(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst); // register to write events bitmask
    const handles_ptr_idx = rs1(inst); // pointer in VM memory to handles array
    const count: usize = @intCast(imm32(inst)); // number of handles

    const handles_addr = vm.regs[handles_ptr_idx];
    const handles_slice = slice_bytes(vm, handles_addr, count * @sizeOf(u64));

    var event_mask: u64 = 0;

    for (0..count) |i| {
        const offset = i * 8;
        const handle_val = std.mem.readInt(u64, handles_slice[offset..][0..8], .big);
        const stream: *anyopaque = @ptrFromInt(handle_val);

        const ready = vm.host.net.?.poll(vm.host.net.?.ctx, stream) catch return error.NotReady;

        // Encode as bitmask: lower bits = readable, next = writable, next = closed
        switch (ready) {
            .readable => event_mask |= (@as(u64, 1) << @as(u6, @intCast(i * 3 + 0))),
            .writable => event_mask |= (@as(u64, 1) << @as(u6, @intCast(i * 3 + 1))),
            .closed => event_mask |= (@as(u64, 1) << @as(u6, @intCast(i * 3 + 2))),
            else => return error.NotReady,
        }
    }

    vm.regs[rd_idx] = event_mask;
}

pub fn net_listen(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const endpoint_ptr_idx = rs1(inst);

    const ep_addr = vm.regs[endpoint_ptr_idx];
    const ep: *const Endpoint = @ptrCast(@alignCast(&vm.memory[@intCast(ep_addr)]));

    const ep_val = ZeusVM.bootstrap.Endpoint{ .ip6 = .{ .addr = ep.ip, .port = ep.port } };
    const listener_val = vm.host.net.?.listen(vm.host.net.?.ctx, ep_val) catch return error.NotReady;

    // Allocate listener struct on heap (opaque handle)
    const listener_ptr = vm.host.allocator.create(ZeusVM.bootstrap.Listener) catch return error.NotReady;
    listener_ptr.* = listener_val;
    vm.regs[rd_idx] = @intFromPtr(listener_ptr);
}

pub fn net_accept(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const handle_idx = rs1(inst);

    const listener: *ZeusVM.bootstrap.Listener = @ptrFromInt(vm.regs[handle_idx]);

    const stream_val = listener.accept(listener.ctx) catch |err| {
        if (err == error.WouldBlock) return error.NotReady else return err;
    };

    const stream_ptr = vm.host.allocator.create(ZeusVM.bootstrap.Stream) catch return error.NotReady;
    stream_ptr.* = stream_val;
    vm.regs[rd_idx] = @intFromPtr(stream_ptr);
}
