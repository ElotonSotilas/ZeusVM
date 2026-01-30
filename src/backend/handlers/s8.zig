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

fn slice_bytes(vm: *VM, addr: u64, len: usize) []u8 {
    const start: usize = @intCast(addr);
    std.debug.assert(start + len <= vm.memory.len);
    return vm.memory[start .. start + len];
}

///==============================
/// Filesystem
///==============================
pub fn fs_open(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const path_ptr_idx = rs1(inst);
    const len: usize = @intCast(imm32(inst));
    // Flags are encoded in rs2: 0=read, 1=write, 2=create+write, etc?
    // Let's assume flags are passed in rs2 as a bitmask or similar.
    // Actually, let's keep it simple: rs2 contains flags directly.
    const path_addr = vm.regs[path_ptr_idx];
    const path = slice_bytes(vm, path_addr, len);

    const flags_val = rs2(inst);

    var flags = ZeusVM.bootstrap.OpenFlags{};
    if (flags_val & 1 != 0) flags.read = true;
    if (flags_val & 2 != 0) flags.write = true;
    if (flags_val & 4 != 0) flags.create = true;
    if (flags_val & 8 != 0) flags.truncate = true;

    const handle = vm.host.fs.?.open(vm.host.fs.?.ctx, path, flags) catch |err| {
        if (err == error.WouldBlock) return error.NotReady;
        return err;
    };
    vm.regs[rd_idx] = @intCast(handle);
}

pub fn fs_read(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const handle_idx = rs1(inst);
    const buf_ptr_idx = rs2(inst);
    const len: usize = @intCast(imm32(inst));

    const handle: ZeusVM.bootstrap.FileHandle = @intCast(vm.regs[handle_idx]);
    const buf_addr = vm.regs[buf_ptr_idx];
    const buf = slice_bytes(vm, buf_addr, len);

    const n = vm.host.fs.?.read(vm.host.fs.?.ctx, handle, buf) catch |err| {
        if (err == error.WouldBlock) return error.NotReady else return err;
    };
    vm.regs[rd_idx] = @intCast(n);
}

pub fn fs_write(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const handle_idx = rs1(inst);
    const buf_ptr_idx = rs2(inst);
    const len: usize = @intCast(imm32(inst));

    const handle: ZeusVM.bootstrap.FileHandle = @intCast(vm.regs[handle_idx]);
    const buf_addr = vm.regs[buf_ptr_idx];
    const buf = slice_bytes(vm, buf_addr, len);

    const n = vm.host.fs.?.write(vm.host.fs.?.ctx, handle, buf) catch |err| {
        if (err == error.WouldBlock) return error.NotReady else return err;
    };
    vm.regs[rd_idx] = @intCast(n);
}

pub fn fs_close(vm: *VM, inst: u64) !void {
    const handle_idx = rs1(inst);
    const handle: ZeusVM.bootstrap.FileHandle = @intCast(vm.regs[handle_idx]);

    vm.host.fs.?.close(vm.host.fs.?.ctx, handle);
    vm.regs[handle_idx] = 0;
}

pub fn load_module(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const path_ptr_idx = rs1(inst);
    const len_idx = rs2(inst);

    const path_addr = vm.regs[path_ptr_idx];
    const len = vm.regs[len_idx];

    // Safety check
    if (path_addr + len > vm.memory.len) return error.OutOfBoundsMemory;

    const path = vm.memory[path_addr..][0..len];

    // Open file
    const file = vm.host.fs.?.open(vm.host.fs.?.ctx, path, .{}) catch |err| {
        std.debug.print("LOAD_MODULE: Failed to open module '{s}': {}\n", .{ path, err });
        return err;
    };
    defer vm.host.fs.?.close(vm.host.fs.?.ctx, file);

    // Get file size
    // Note: vm.host.fs doesn't expose stat directly easily, but we can read it.
    // Actually, we can assume the host implementation allows us to read until EOF or we can rely on standard IO if we had it.
    // However, vm.host.fs works with handles.
    // Let's use vm.host.fs.read into memory.

    // We need to know size to verify we have space.
    // Since we don't have GetFileSize in our Host interface explicitly shown in s8 previous context,
    // let's assume we just read into the memory at next_free_addr.

    // Check if we have space left in VM memory
    if (vm.next_free_addr >= vm.memory.len) return error.OutOfMemory;

    const dest = vm.memory[vm.next_free_addr..];

    const read = vm.host.fs.?.read(vm.host.fs.?.ctx, file, dest) catch |err| {
        std.debug.print("LOAD_MODULE: Failed to read module: {}\n", .{err});
        return err;
    };

    // Return the load address
    vm.regs[rd_idx] = @intCast(vm.next_free_addr);

    // Update next free address (aligned to 8 bytes)
    vm.next_free_addr += (read + 7) & ~@as(usize, 7);
}

///==============================
/// Stdio
///==============================
pub fn stdin_read(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const buf_ptr_idx = rs1(inst);
    const len: usize = @intCast(imm32(inst));

    const buf_addr = vm.regs[buf_ptr_idx];
    const buf = slice_bytes(vm, buf_addr, len);

    if (vm.host.io.stdin) |in| {
        const n = in.read(in.ctx, buf) catch |err| {
            if (err == error.WouldBlock) return error.NotReady else return err;
        };
        vm.regs[rd_idx] = @intCast(n);
    } else {
        vm.regs[rd_idx] = 0; // EOF/No Input
    }
}

pub fn stdout_write(vm: *VM, inst: u64) !void {
    const buf_ptr_idx = rs1(inst);
    const len: usize = @intCast(imm32(inst));

    const buf_addr = vm.regs[buf_ptr_idx];
    const buf = slice_bytes(vm, buf_addr, len);

    if (vm.host.io.stdout) |out| {
        // Ignore write error? Or return in Rd?
        // Opcode allows return in Rd?
        // Instruction format: STDOUT_WRITE Rs1, Imm. (No Rd).
        // Opcode def usually has Rd field.
        // If we want return value support, we need to decide instruction format.
        // Let's assume fire-and-forget or panic on failure?
        // fs_write returns count.
        // Let's match fs_write behavior but update instruction format if Rd expected.
        // User asked for "faster printing". Void return is fastest.
        _ = out.write(out.ctx, buf) catch {};
    }
}

pub fn stderr_write(vm: *VM, inst: u64) !void {
    const buf_ptr_idx = rs1(inst);
    const len: usize = @intCast(imm32(inst));

    const buf_addr = vm.regs[buf_ptr_idx];
    const buf = slice_bytes(vm, buf_addr, len);

    if (vm.host.io.stderr) |err_out| {
        _ = err_out.write(err_out.ctx, buf) catch {};
    }
}
