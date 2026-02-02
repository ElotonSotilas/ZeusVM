const std = @import("std");
const ZeusVM = @import("../../root.zig");
const VM = ZeusVM.vm.VM;

///==============================
/// Helpers
///==============================
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
/// Dynamic Library Operations
///==============================
pub fn dl_open(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const rs_idx = rs1(inst);
    const ptr = vm.regs[rs_idx];

    // Read string (find NULL terminator)
    const max_len = 1024;
    const slice = slice_bytes(vm, ptr, max_len);
    const len = std.mem.indexOfScalar(u8, slice, 0) orelse max_len;

    if (vm.host.library) |lib| {
        vm.regs[rd_idx] = try lib.open(lib.ctx, slice[0..len]);
    } else return error.LibrarySupportMissing;
}

pub fn dl_sym(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const handle_idx = rs1(inst);
    const symbol_idx = rs2(inst);

    const handle = vm.regs[handle_idx];
    const ptr = vm.regs[symbol_idx];

    const max_len = 256;
    const slice = slice_bytes(vm, ptr, max_len);
    const len = std.mem.indexOfScalar(u8, slice, 0) orelse max_len;

    if (vm.host.library) |lib| {
        vm.regs[rd_idx] = try lib.lookup(lib.ctx, handle, slice[0..len]);
    } else return error.LibrarySupportMissing;
}

pub fn dl_call(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const addr_idx = rs1(inst);
    const args_idx = rs2(inst);

    const addr = vm.regs[addr_idx];
    const args_ptr = vm.regs[args_idx];

    // ArgBlock: count(u64), mask(u64), args([u64]...)
    const header_slice = slice_bytes(vm, args_ptr, 16);
    const count_val = std.mem.readInt(u64, header_slice[0..8], .big);
    const type_mask: u64 = std.mem.readInt(u64, header_slice[8..16], .big);

    if (count_val > 16) return error.TooManyArguments;

    // Convert Big Endian VM args to Host Endian for the FFI call
    var temp_args: [16]u64 = undefined;
    const args_start = args_ptr + 16;
    const args_slice = slice_bytes(vm, args_start, @intCast(count_val * 8));

    var i: usize = 0;
    while (i < count_val) : (i += 1) {
        const arg_bytes = args_slice[i * 8 .. (i + 1) * 8];
        temp_args[i] = std.mem.readInt(u64, arg_bytes[0..8], .big);
    }

    if (vm.host.library) |lib| {
        vm.regs[rd_idx] = lib.call(lib.ctx, addr, &temp_args, type_mask, @intCast(count_val), vm.memory.ptr, vm.memory.len);
    } else return error.LibrarySupportMissing;
}

pub fn dl_close(vm: *VM, inst: u64) !void {
    const handle_idx = rs1(inst);
    const handle = vm.regs[handle_idx];
    if (vm.host.library) |lib| {
        lib.close(lib.ctx, handle);
    } else return error.LibrarySupportMissing;
}
