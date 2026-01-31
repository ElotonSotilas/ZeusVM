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
/// Vector Operations
///==============================
pub fn v128_load(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const addr_idx = rs1(inst);
    const addr = vm.regs[addr_idx];

    const slice = slice_bytes(vm, addr, 16);
    const vec: @Vector(16, u8) = @bitCast(slice[0..16].*);
    vm.vregs[rd_idx] = vec; // store as vector register
}

pub fn v128_store(vm: *VM, inst: u64) !void {
    const addr_idx = rs1(inst);
    const rd_idx = rd(inst);
    const addr = vm.regs[addr_idx];

    const vec: @Vector(16, u8) = vm.vregs[rd_idx];
    const slice = slice_bytes(vm, addr, 16);
    const bytes: [16]u8 = @as([16]u8, @bitCast(vec)); // write back
    @memcpy(slice, &bytes);
}

/// Arithmetic (element-wise)
pub fn v128_add(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);

    const a: @Vector(16, u8) = vm.vregs[a_idx];
    const b: @Vector(16, u8) = vm.vregs[b_idx];

    vm.vregs[rd_idx] = a + b; // element-wise addition
}

pub fn v128_sub(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);

    vm.vregs[rd_idx] = vm.vregs[a_idx] - vm.vregs[b_idx];
}

pub fn v128_mul(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);

    vm.vregs[rd_idx] = vm.vregs[a_idx] * vm.vregs[b_idx];
}

/// Bitwise
pub fn v128_and(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);

    vm.vregs[rd_idx] = vm.vregs[a_idx] & vm.vregs[b_idx];
}

pub fn v128_or(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);

    vm.vregs[rd_idx] = vm.vregs[a_idx] | vm.vregs[b_idx];
}

pub fn v128_xor(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);

    vm.vregs[rd_idx] = vm.vregs[a_idx] ^ vm.vregs[b_idx];
}

/// Shuffle (example: XOR shuffle, can be replaced with real permutation table)
pub fn v128_shuffle(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);

    const a = vm.vregs[a_idx];
    const b = vm.vregs[b_idx];

    // simple xor-based shuffle as placeholder
    vm.vregs[rd_idx] = a ^ b;
}

pub fn v128_f64x2_add(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    const a: @Vector(2, f64) = @bitCast(vm.vregs[a_idx]);
    const b: @Vector(2, f64) = @bitCast(vm.vregs[b_idx]);
    vm.vregs[rd_idx] = @bitCast(a + b);
}

pub fn v128_f64x2_sub(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    const a: @Vector(2, f64) = @bitCast(vm.vregs[a_idx]);
    const b: @Vector(2, f64) = @bitCast(vm.vregs[b_idx]);
    vm.vregs[rd_idx] = @bitCast(a - b);
}

pub fn v128_f64x2_mul(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    const a: @Vector(2, f64) = @bitCast(vm.vregs[a_idx]);
    const b: @Vector(2, f64) = @bitCast(vm.vregs[b_idx]);
    vm.vregs[rd_idx] = @bitCast(a * b);
}

pub fn v128_f64x2_div(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    const a: @Vector(2, f64) = @bitCast(vm.vregs[a_idx]);
    const b: @Vector(2, f64) = @bitCast(vm.vregs[b_idx]);
    vm.vregs[rd_idx] = @bitCast(a / b);
}

pub fn v128_f64x2_sqrt(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const a: @Vector(2, f64) = @bitCast(vm.vregs[a_idx]);
    vm.vregs[rd_idx] = @bitCast(@sqrt(a));
}

pub fn v128_splat_f64(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const rs_idx = rs1(inst);
    const val: f64 = @bitCast(vm.regs[rs_idx]);
    const vec: @Vector(2, f64) = @splat(val);
    vm.vregs[rd_idx] = @bitCast(vec);
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
