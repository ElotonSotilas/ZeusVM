const std = @import("std");
const ZeusVM = @import("../../root.zig");
const Opcode = ZeusVM.opcode.Opcode;
const VM = ZeusVM.vm.VM;

/// Helpers
fn rd(instruction: u64) u8 {
    return @intCast((instruction >> 48) & 0xFF);
}
fn rs1(instruction: u64) u8 {
    return @intCast((instruction >> 40) & 0xFF);
}
fn rs2(instruction: u64) u8 {
    return @intCast((instruction >> 32) & 0xFF);
}

//================================================================================
// Floating Point Arithmetic (F64)
//================================================================================

pub fn fadd(vm: *VM, inst: u64) !void {
    const a: f64 = @bitCast(vm.regs[rs1(inst)]);
    const b: f64 = @bitCast(vm.regs[rs2(inst)]);
    vm.regs[rd(inst)] = @bitCast(a + b);
}

pub fn fsub(vm: *VM, inst: u64) !void {
    const a: f64 = @bitCast(vm.regs[rs1(inst)]);
    const b: f64 = @bitCast(vm.regs[rs2(inst)]);
    vm.regs[rd(inst)] = @bitCast(a - b);
}

pub fn fmul(vm: *VM, inst: u64) !void {
    const a: f64 = @bitCast(vm.regs[rs1(inst)]);
    const b: f64 = @bitCast(vm.regs[rs2(inst)]);
    vm.regs[rd(inst)] = @bitCast(a * b);
}

pub fn fdiv(vm: *VM, inst: u64) !void {
    const a: f64 = @bitCast(vm.regs[rs1(inst)]);
    const b: f64 = @bitCast(vm.regs[rs2(inst)]);
    vm.regs[rd(inst)] = @bitCast(a / b);
}

pub fn fneg(vm: *VM, inst: u64) !void {
    const a: f64 = @bitCast(vm.regs[rs1(inst)]);
    vm.regs[rd(inst)] = @bitCast(-a);
}

pub fn fabs(vm: *VM, inst: u64) !void {
    const a: f64 = @bitCast(vm.regs[rs1(inst)]);
    vm.regs[rd(inst)] = @bitCast(@abs(a));
}

pub fn fsqrt(vm: *VM, inst: u64) !void {
    const a: f64 = @bitCast(vm.regs[rs1(inst)]);
    vm.regs[rd(inst)] = @bitCast(@sqrt(a));
}

//================================================================================
// Floating Point Comparison
//================================================================================

pub fn fcmp_eq(vm: *VM, inst: u64) !void {
    const a: f64 = @bitCast(vm.regs[rs1(inst)]);
    const b: f64 = @bitCast(vm.regs[rs2(inst)]);
    vm.regs[rd(inst)] = if (a == b) 1 else 0;
}

pub fn fcmp_ne(vm: *VM, inst: u64) !void {
    const a: f64 = @bitCast(vm.regs[rs1(inst)]);
    const b: f64 = @bitCast(vm.regs[rs2(inst)]);
    vm.regs[rd(inst)] = if (a != b) 1 else 0;
}

pub fn fcmp_lt(vm: *VM, inst: u64) !void {
    const a: f64 = @bitCast(vm.regs[rs1(inst)]);
    const b: f64 = @bitCast(vm.regs[rs2(inst)]);
    vm.regs[rd(inst)] = if (a < b) 1 else 0;
}

pub fn fcmp_gt(vm: *VM, inst: u64) !void {
    const a: f64 = @bitCast(vm.regs[rs1(inst)]);
    const b: f64 = @bitCast(vm.regs[rs2(inst)]);
    vm.regs[rd(inst)] = if (a > b) 1 else 0;
}

pub fn fcmp_le(vm: *VM, inst: u64) !void {
    const a: f64 = @bitCast(vm.regs[rs1(inst)]);
    const b: f64 = @bitCast(vm.regs[rs2(inst)]);
    vm.regs[rd(inst)] = if (a <= b) 1 else 0;
}

pub fn fcmp_ge(vm: *VM, inst: u64) !void {
    const a: f64 = @bitCast(vm.regs[rs1(inst)]);
    const b: f64 = @bitCast(vm.regs[rs2(inst)]);
    vm.regs[rd(inst)] = if (a >= b) 1 else 0;
}

//================================================================================
// Conversion
//================================================================================

pub fn fconv_i2f(vm: *VM, inst: u64) !void {
    const a: i64 = @bitCast(vm.regs[rs1(inst)]);
    const f: f64 = @floatFromInt(a);
    vm.regs[rd(inst)] = @bitCast(f);
}

pub fn fconv_f2i(vm: *VM, inst: u64) !void {
    const f: f64 = @bitCast(vm.regs[rs1(inst)]);
    const a: i64 = @intFromFloat(f);
    vm.regs[rd(inst)] = @bitCast(a);
}
