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

///==============================
/// Memory Operations
///==============================
pub fn load(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const base_idx = rs1(inst);
    const offset: usize = @intCast(imm32(inst));
    const addr: usize = @as(usize, @intCast(vm.regs[base_idx])) + offset;

    std.debug.assert(addr + 8 <= vm.memory.len);
    std.debug.assert(addr + 8 <= vm.memory.len);
    const slice = slice64(vm.memory, addr);
    vm.regs[rd_idx] = std.mem.readInt(u64, @ptrCast(slice.ptr), .big);
}

pub fn store(vm: *VM, inst: u64) !void {
    const base_idx = rs1(inst);
    const rd_idx = rd(inst);
    const offset: usize = @intCast(imm32(inst));
    const addr: usize = @as(usize, @intCast(vm.regs[base_idx])) + offset;

    std.debug.assert(addr + 8 <= vm.memory.len);
    std.debug.assert(addr + 8 <= vm.memory.len);
    const slice = slice64(vm.memory, addr);
    std.mem.writeInt(u64, @as(*[8]u8, @ptrCast(slice.ptr)), vm.regs[rd_idx], .big);
}

pub fn mem_copy(vm: *VM, inst: u64) !void {
    const dst_base = rs1(inst);
    const src_base = rs2(inst);
    const n_bytes: usize = @intCast(imm32(inst));

    const dst_addr: usize = @intCast(vm.regs[dst_base]);
    const src_addr: usize = @intCast(vm.regs[src_base]);

    std.debug.assert(src_addr + n_bytes <= vm.memory.len);
    std.debug.assert(dst_addr + n_bytes <= vm.memory.len);

    @memcpy(vm.memory[dst_addr .. dst_addr + n_bytes], vm.memory[src_addr .. src_addr + n_bytes]);
}

pub fn mem_zero(vm: *VM, inst: u64) !void {
    const base_idx = rs1(inst);
    const n_bytes: usize = @intCast(imm32(inst));
    const addr: usize = @intCast(vm.regs[base_idx]);

    std.debug.assert(addr + n_bytes <= vm.memory.len);
    @memset(vm.memory[addr .. addr + n_bytes], 0);
}

///==============================
/// Heap Operations
///==============================
pub fn heap_alloc(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const n_bytes: usize = @intCast(imm32(inst));

    // alloc returns offset into vm.memory
    // alloc returns offset into vm.memory
    // Heap not implemented yet
    _ = n_bytes;
    const addr = 0;
    // const addr = vm.heap.alloc(n_bytes) catch unreachable;
    vm.regs[rd_idx] = @intCast(addr);
}

pub fn heap_free(vm: *VM, inst: u64) !void {
    const base_idx = rs1(inst);
    const addr: usize = @intCast(vm.regs[base_idx]);

    // vm.heap.free(addr) catch unreachable;
    _ = addr;
}

///==============================
/// Pointer Arithmetic
///==============================
pub fn ptr_add(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const base_idx = rs1(inst);
    const offset: u64 = @intCast(imm32(inst));
    vm.regs[rd_idx] = vm.regs[base_idx] + offset;
}

pub fn ptr_sub(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const base_idx = rs1(inst);
    const offset: u64 = @intCast(imm32(inst));
    vm.regs[rd_idx] = vm.regs[base_idx] - offset;
}
