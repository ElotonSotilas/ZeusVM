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

fn slice_bytes(vm: *VM, addr: u64, len: usize) []u8 {
    const start: usize = @intCast(addr);
    std.debug.assert(start + len <= vm.memory.len);
    return vm.memory[start .. start + len];
}

///==============================
/// V512 (64B) Vector Operations
///==============================
pub fn v512_load(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const addr_idx = rs1(inst);
    const addr = vm.regs[addr_idx];

    const slice = slice_bytes(vm, addr, 64);
    vm.v512regs[rd_idx] = @bitCast(slice[0..64].*);
}

pub fn v512_store(vm: *VM, inst: u64) !void {
    const addr_idx = rs1(inst);
    const rd_idx = rd(inst);
    const addr = vm.regs[addr_idx];

    const vec = vm.v512regs[rd_idx];
    const slice = slice_bytes(vm, addr, 64);
    const bytes: [64]u8 = @bitCast(vec);
    @memcpy(slice, &bytes);
}

pub fn v512_add(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    vm.v512regs[rd_idx] = vm.v512regs[a_idx] + vm.v512regs[b_idx];
}

pub fn v512_sub(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    vm.v512regs[rd_idx] = vm.v512regs[a_idx] - vm.v512regs[b_idx];
}

pub fn v512_mul(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    vm.v512regs[rd_idx] = vm.v512regs[a_idx] * vm.v512regs[b_idx];
}

pub fn v512_and(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    vm.v512regs[rd_idx] = vm.v512regs[a_idx] & vm.v512regs[b_idx];
}

pub fn v512_or(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    vm.v512regs[rd_idx] = vm.v512regs[a_idx] | vm.v512regs[b_idx];
}

pub fn v512_xor(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    vm.v512regs[rd_idx] = vm.v512regs[a_idx] ^ vm.v512regs[b_idx];
}

pub fn v512_f64x8_add(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    const a: @Vector(8, f64) = @bitCast(vm.v512regs[a_idx]);
    const b: @Vector(8, f64) = @bitCast(vm.v512regs[b_idx]);
    vm.v512regs[rd_idx] = @bitCast(a + b);
}

pub fn v512_f64x8_sub(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    const a: @Vector(8, f64) = @bitCast(vm.v512regs[a_idx]);
    const b: @Vector(8, f64) = @bitCast(vm.v512regs[b_idx]);
    vm.v512regs[rd_idx] = @bitCast(a - b);
}

pub fn v512_f64x8_mul(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    const a: @Vector(8, f64) = @bitCast(vm.v512regs[a_idx]);
    const b: @Vector(8, f64) = @bitCast(vm.v512regs[b_idx]);
    vm.v512regs[rd_idx] = @bitCast(a * b);
}

pub fn v512_f64x8_div(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    const a: @Vector(8, f64) = @bitCast(vm.v512regs[a_idx]);
    const b: @Vector(8, f64) = @bitCast(vm.v512regs[b_idx]);
    vm.v512regs[rd_idx] = @bitCast(a / b);
}

pub fn v512_f64x8_sqrt(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const a: @Vector(8, f64) = @bitCast(vm.v512regs[a_idx]);
    vm.v512regs[rd_idx] = @bitCast(@sqrt(a));
}

pub fn v512_splat_f64(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const rs_idx = rs1(inst);
    const val: f64 = @bitCast(vm.regs[rs_idx]);
    const vec: @Vector(8, f64) = @splat(val);
    vm.v512regs[rd_idx] = @bitCast(vec);
}

pub fn v512_shuffle(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    // Placeholder XOR shuffle (same as v128)
    vm.v512regs[rd_idx] = vm.v512regs[a_idx] ^ vm.v512regs[b_idx];
}

///==============================
/// V2048 (256B) Vector Operations
///==============================
pub fn v2048_load(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const addr_idx = rs1(inst);
    const addr = vm.regs[addr_idx];

    const slice = slice_bytes(vm, addr, 256);
    vm.v2048regs[rd_idx] = @bitCast(slice[0..256].*);
}

pub fn v2048_store(vm: *VM, inst: u64) !void {
    const addr_idx = rs1(inst);
    const rd_idx = rd(inst);
    const addr = vm.regs[addr_idx];

    const vec = vm.v2048regs[rd_idx];
    const slice = slice_bytes(vm, addr, 256);
    const bytes: [256]u8 = @bitCast(vec);
    @memcpy(slice, &bytes);
}

pub fn v2048_add(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    vm.v2048regs[rd_idx] = vm.v2048regs[a_idx] + vm.v2048regs[b_idx];
}

pub fn v2048_sub(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    vm.v2048regs[rd_idx] = vm.v2048regs[a_idx] - vm.v2048regs[b_idx];
}

pub fn v2048_mul(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    vm.v2048regs[rd_idx] = vm.v2048regs[a_idx] * vm.v2048regs[b_idx];
}

pub fn v2048_and(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    vm.v2048regs[rd_idx] = vm.v2048regs[a_idx] & vm.v2048regs[b_idx];
}

pub fn v2048_or(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    vm.v2048regs[rd_idx] = vm.v2048regs[a_idx] | vm.v2048regs[b_idx];
}

pub fn v2048_xor(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    vm.v2048regs[rd_idx] = vm.v2048regs[a_idx] ^ vm.v2048regs[b_idx];
}

pub fn v2048_f64x32_add(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    const a: @Vector(32, f64) = @bitCast(vm.v2048regs[a_idx]);
    const b: @Vector(32, f64) = @bitCast(vm.v2048regs[b_idx]);
    vm.v2048regs[rd_idx] = @bitCast(a + b);
}

pub fn v2048_f64x32_sub(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    const a: @Vector(32, f64) = @bitCast(vm.v2048regs[a_idx]);
    const b: @Vector(32, f64) = @bitCast(vm.v2048regs[b_idx]);
    vm.v2048regs[rd_idx] = @bitCast(a - b);
}

pub fn v2048_f64x32_mul(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    const a: @Vector(32, f64) = @bitCast(vm.v2048regs[a_idx]);
    const b: @Vector(32, f64) = @bitCast(vm.v2048regs[b_idx]);
    vm.v2048regs[rd_idx] = @bitCast(a * b);
}

pub fn v2048_f64x32_div(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    const a: @Vector(32, f64) = @bitCast(vm.v2048regs[a_idx]);
    const b: @Vector(32, f64) = @bitCast(vm.v2048regs[b_idx]);
    vm.v2048regs[rd_idx] = @bitCast(a / b);
}

pub fn v2048_f64x32_sqrt(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const a: @Vector(32, f64) = @bitCast(vm.v2048regs[a_idx]);
    vm.v2048regs[rd_idx] = @bitCast(@sqrt(a));
}

pub fn v2048_splat_f64(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const rs_idx = rs1(inst);
    const val: f64 = @bitCast(vm.regs[rs_idx]);
    const vec: @Vector(32, f64) = @splat(val);
    vm.v2048regs[rd_idx] = @bitCast(vec);
}

pub fn v2048_shuffle(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    // Placeholder XOR shuffle (same as v128)
    vm.v2048regs[rd_idx] = vm.v2048regs[a_idx] ^ vm.v2048regs[b_idx];
}
