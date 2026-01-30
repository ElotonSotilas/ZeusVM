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

// Get aligned pointer to u64 in VM memory
fn get_atomic_ptr(vm: *VM, addr: usize) !*u64 {
    if (addr + 8 > vm.memory.len) return error.OutOfBoundsMemory;
    if (addr % 8 != 0) return error.UnalignedAccess;
    return @ptrCast(@alignCast(&vm.memory[addr]));
}

///==============================
/// Atomic Instructions
///==============================
pub fn atomic_load(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const ptr_idx = rs1(inst);
    // order ignored for now (SeqCst assumed) or parsed from imm?

    const addr: usize = @intCast(vm.regs[ptr_idx]);
    const ptr = try get_atomic_ptr(vm, addr);

    const val = @atomicLoad(u64, ptr, .seq_cst);
    vm.regs[rd_idx] = val;
}

pub fn atomic_store(vm: *VM, inst: u64) !void {
    const ptr_idx = rs1(inst);
    const val_idx = rs2(inst);

    const addr: usize = @intCast(vm.regs[ptr_idx]);
    const ptr = try get_atomic_ptr(vm, addr);
    const val = vm.regs[val_idx];

    @atomicStore(u64, ptr, val, .seq_cst);
}

pub fn atomic_rmw(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const ptr_idx = rs1(inst);
    const val_idx = rs2(inst);
    const op_code = imm32(inst);

    const addr: usize = @intCast(vm.regs[ptr_idx]);
    const ptr = try get_atomic_ptr(vm, addr);
    const operand = vm.regs[val_idx];

    const old_val = switch (op_code) {
        0 => @atomicRmw(u64, ptr, .Add, operand, .seq_cst),
        1 => @atomicRmw(u64, ptr, .Sub, operand, .seq_cst),
        2 => @atomicRmw(u64, ptr, .And, operand, .seq_cst),
        3 => @atomicRmw(u64, ptr, .Or, operand, .seq_cst),
        4 => @atomicRmw(u64, ptr, .Xor, operand, .seq_cst),
        5 => @atomicRmw(u64, ptr, .Xchg, operand, .seq_cst),
        else => return error.InvalidInstruction,
    };

    vm.regs[rd_idx] = old_val;
}

pub fn atomic_cas(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const ptr_idx = rs1(inst);
    const expected_idx = rs2(inst);

    const addr: usize = @intCast(vm.regs[ptr_idx]);
    const ptr = try get_atomic_ptr(vm, addr);

    const expected = vm.regs[expected_idx];
    const new_val = vm.regs[rd_idx]; // Rd used as input (new) AND output (old)

    const result = @cmpxchgStrong(u64, ptr, expected, new_val, .seq_cst, .seq_cst);

    // result is ?u64. null if success (value matched expected), or wrong_value if fail.
    // Spec: Return OLD value in Rd.
    // If success: Old value WAS expected.
    // If fail: result is Old value.
    if (result) |actual_old| {
        vm.regs[rd_idx] = actual_old;
    } else {
        vm.regs[rd_idx] = expected;
    }
}
