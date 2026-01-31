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

/// =======================
/// Core Control Flow
/// =======================
pub fn nop(vm: *VM, instruction: u64) !void {
    _ = instruction;
    _ = vm;
}

pub fn halt(vm: *VM, instruction: u64) !void {
    _ = instruction;
    vm.running = false;
}

pub fn jmp(vm: *VM, instruction: u64) !void {
    const target = @as(usize, imm32(instruction));
    vm.pc = target;
}

pub fn br(vm: *VM, instruction: u64) !void {
    const rs = rs1(instruction);
    const target = @as(usize, imm32(instruction));
    if (vm.regs[rs] != 0) {
        vm.pc = target;
    }
}

pub fn br_if(vm: *VM, instruction: u64) !void {
    const cond_reg = rs1(instruction);
    const target = @as(usize, imm32(instruction));
    if (vm.regs[cond_reg] != 0) {
        vm.pc = target;
    }
}

pub fn call(vm: *VM, instruction: u64) !void {
    const target = @as(usize, imm32(instruction));
    // push return address (next instruction)
    vm.stack[vm.sp] = @intCast(vm.pc + 8);
    vm.sp += 1;
    vm.pc = target;
}

pub fn call_reg(vm: *VM, instruction: u64) !void {
    const rs = rs1(instruction);
    const target = @as(usize, @intCast(vm.regs[rs]));
    // push return address (next instruction)
    vm.stack[vm.sp] = @intCast(vm.pc + 8);
    vm.sp += 1;
    vm.pc = target;
}

pub fn ret(vm: *VM, instruction: u64) !void {
    _ = instruction;
    // pop return address
    vm.sp -= 1;
    vm.pc = @as(usize, @intCast(vm.stack[vm.sp]));
}
