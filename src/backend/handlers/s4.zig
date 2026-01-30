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

//================================================================================
// Integer Comparisons
//================================================================================

pub fn icmp_eq(vm: *VM, inst: u64) !void {
    vm.regs[rd(inst)] = if (vm.regs[rs1(inst)] == vm.regs[rs2(inst)]) 1 else 0;
}

pub fn icmp_ne(vm: *VM, inst: u64) !void {
    vm.regs[rd(inst)] = if (vm.regs[rs1(inst)] != vm.regs[rs2(inst)]) 1 else 0;
}

pub fn icmp_lt(vm: *VM, inst: u64) !void {
    vm.regs[rd(inst)] = if (vm.regs[rs1(inst)] < vm.regs[rs2(inst)]) 1 else 0;
}

pub fn icmp_gt(vm: *VM, inst: u64) !void {
    vm.regs[rd(inst)] = if (vm.regs[rs1(inst)] > vm.regs[rs2(inst)]) 1 else 0;
}

pub fn icmp_le(vm: *VM, inst: u64) !void {
    vm.regs[rd(inst)] = if (vm.regs[rs1(inst)] <= vm.regs[rs2(inst)]) 1 else 0;
}

pub fn icmp_ge(vm: *VM, inst: u64) !void {
    vm.regs[rd(inst)] = if (vm.regs[rs1(inst)] >= vm.regs[rs2(inst)]) 1 else 0;
}
