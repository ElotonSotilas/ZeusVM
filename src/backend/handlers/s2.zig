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
fn imm32(instruction: u64) u32 {
    return @intCast(instruction & 0xffff_ffff);
}

//================================================================================
// Integer Arithmetic
//================================================================================

pub fn iadd(vm: *VM, inst: u64) !void {
    vm.regs[rd(inst)] = vm.regs[rs1(inst)] + vm.regs[rs2(inst)];
}

pub fn isub(vm: *VM, inst: u64) !void {
    vm.regs[rd(inst)] = vm.regs[rs1(inst)] - vm.regs[rs2(inst)];
}

pub fn imul(vm: *VM, inst: u64) !void {
    vm.regs[rd(inst)] = vm.regs[rs1(inst)] * vm.regs[rs2(inst)];
}

pub fn idiv(vm: *VM, inst: u64) !void {
    // unsigned division
    vm.regs[rd(inst)] = vm.regs[rs1(inst)] / vm.regs[rs2(inst)];
}

pub fn imod(vm: *VM, inst: u64) !void {
    vm.regs[rd(inst)] = vm.regs[rs1(inst)] % vm.regs[rs2(inst)];
}

pub fn iand(vm: *VM, inst: u64) !void {
    vm.regs[rd(inst)] = vm.regs[rs1(inst)] & vm.regs[rs2(inst)];
}

pub fn ior(vm: *VM, inst: u64) !void {
    vm.regs[rd(inst)] = vm.regs[rs1(inst)] | vm.regs[rs2(inst)];
}

pub fn ixor(vm: *VM, inst: u64) !void {
    vm.regs[rd(inst)] = vm.regs[rs1(inst)] ^ vm.regs[rs2(inst)];
}

pub fn ishl(vm: *VM, inst: u64) !void {
    const shift: u64 = @intCast(vm.regs[rs2(inst)] & 0x3F);
    vm.regs[rd(inst)] = vm.regs[rs1(inst)] << @as(u6, @intCast(shift));
}

pub fn ishr(vm: *VM, inst: u64) !void {
    const shift: u64 = @intCast(vm.regs[rs2(inst)] & 0x3F);
    vm.regs[rd(inst)] = vm.regs[rs1(inst)] >> @as(u6, @intCast(shift));
}
