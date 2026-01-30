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
/// Time & Sleep
///==============================
pub fn time_now(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    // call the user-provided monotonic_ns function
    vm.regs[rd_idx] = vm.host.time.?.monotonic_ns(vm.host.time.?.ctx);
}

pub fn sleep_ns(vm: *VM, inst: u64) !void {
    const ns: u64 = @intCast(imm32(inst));
    // pretend we have a sleep function that returns WouldBlock
    vm.host.time.?.sleep_ns(vm.host.time.?.ctx, ns) catch |err| {
        if (err == error.WouldBlock) return error.NotReady else return err;
    };
}

///==============================
/// Threading
///==============================
pub fn thread_spawn(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const entry_addr = imm32(inst);

    // call user-provided thread spawn function
    // Hack: pass 0 as arg, cast entry to fn ptr
    const fn_ptr: *const fn (*anyopaque) void = @ptrFromInt(entry_addr);
    const thread_id = vm.host.threading.?.spawn(vm.host.threading.?.ctx, fn_ptr, @ptrFromInt(1)) catch return error.NotReady;
    vm.regs[rd_idx] = @intCast(thread_id);
}

pub fn thread_join(vm: *VM, inst: u64) !void {
    const thread_idx = rs1(inst);
    const thread_id: u32 = @intCast(vm.regs[thread_idx]);

    vm.host.threading.?.join(vm.host.threading.?.ctx, thread_id) catch return error.NotReady;
}

pub fn thread_yield(vm: *VM, inst: u64) !void {
    _ = inst;
    vm.host.threading.?.yield(vm.host.threading.?.ctx);
}
