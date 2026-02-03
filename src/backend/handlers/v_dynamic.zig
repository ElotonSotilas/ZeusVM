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

fn v_len(inst: u64) u32 {
    return @intCast(inst & 0xFFFFFFFF);
}

fn slice_bytes(vm: *VM, addr: u64, len: usize) []u8 {
    const start: usize = @intCast(addr);
    std.debug.assert(start + len <= vm.memory.len);
    return vm.memory[start .. start + len];
}

fn ceilPowerOfTwo(len: u32) u32 {
    if (len == 0) return 0;
    const p2 = std.math.ceilPowerOfTwo(u32, len) catch len;
    return @max(p2, 32);
}

fn ensureCapacity(vm: *VM, reg_idx: u8, desired_len: u32) ![]u8 {
    const padded_len = ceilPowerOfTwo(desired_len);
    if (vm.vreg_caps[reg_idx] < padded_len) {
        if (vm.vregs[reg_idx].len > 0) {
            vm.host.allocator.free(vm.vregs[reg_idx]);
        }
        vm.vregs[reg_idx] = try vm.host.allocator.alloc(u8, padded_len);
        vm.vreg_caps[reg_idx] = padded_len;
    }
    // Always zero pad the tail if we are using it for a shorter logical length
    if (vm.vregs[reg_idx].len > desired_len) {
        @memset(vm.vregs[reg_idx][desired_len..], 0);
    }
    return vm.vregs[reg_idx];
}

///==============================
/// Dynamic Vector Operations
///==============================
pub fn v_load(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const addr_idx = rs1(inst);
    const len = v_len(inst);
    const addr = vm.regs[addr_idx];

    const reg_buf = try ensureCapacity(vm, rd_idx, len);
    const mem_slice = slice_bytes(vm, addr, len);
    @memcpy(reg_buf[0..len], mem_slice);
}

pub fn v_store(vm: *VM, inst: u64) !void {
    const addr_idx = rs1(inst);
    const rd_idx = rd(inst);
    const len = v_len(inst);
    const addr = vm.regs[addr_idx];

    const vec = vm.vregs[rd_idx];
    if (vec.len < len) return error.VectorTooSmall;

    const mem_slice = slice_bytes(vm, addr, len);
    @memcpy(mem_slice, vec[0..len]);
}

pub fn v_add(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    const len = v_len(inst);

    const a = vm.vregs[a_idx];
    const b = vm.vregs[b_idx];
    if (a.len < len or b.len < len) return error.VectorTooSmall;

    const res = try ensureCapacity(vm, rd_idx, len);
    var i: usize = 0;
    while (i < len) : (i += 32) {
        const va: @Vector(32, u8) = a[i..][0..32].*;
        const vb: @Vector(32, u8) = b[i..][0..32].*;
        res[i..][0..32].* = va +% vb;
    }
}

pub fn v_sub(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    const len = v_len(inst);

    const a = vm.vregs[a_idx];
    const b = vm.vregs[b_idx];
    if (a.len < len or b.len < len) return error.VectorTooSmall;

    const res = try ensureCapacity(vm, rd_idx, len);
    var i: usize = 0;
    while (i < len) : (i += 32) {
        const va: @Vector(32, u8) = a[i..][0..32].*;
        const vb: @Vector(32, u8) = b[i..][0..32].*;
        res[i..][0..32].* = va -% vb;
    }
}

pub fn v_mul(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    const len = v_len(inst);

    const a = vm.vregs[a_idx];
    const b = vm.vregs[b_idx];
    if (a.len < len or b.len < len) return error.VectorTooSmall;

    const res = try ensureCapacity(vm, rd_idx, len);
    var i: usize = 0;
    while (i < len) : (i += 32) {
        const va: @Vector(32, u8) = a[i..][0..32].*;
        const vb: @Vector(32, u8) = b[i..][0..32].*;
        res[i..][0..32].* = va *% vb;
    }
}

pub fn v_and(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    const len = v_len(inst);

    const a = vm.vregs[a_idx];
    const b = vm.vregs[b_idx];
    if (a.len < len or b.len < len) return error.VectorTooSmall;

    const res = try ensureCapacity(vm, rd_idx, len);
    var i: usize = 0;
    while (i < len) : (i += 32) {
        const va: @Vector(32, u8) = a[i..][0..32].*;
        const vb: @Vector(32, u8) = b[i..][0..32].*;
        res[i..][0..32].* = va & vb;
    }
}

pub fn v_or(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    const len = v_len(inst);

    const a = vm.vregs[a_idx];
    const b = vm.vregs[b_idx];
    if (a.len < len or b.len < len) return error.VectorTooSmall;

    const res = try ensureCapacity(vm, rd_idx, len);
    var i: usize = 0;
    while (i < len) : (i += 32) {
        const va: @Vector(32, u8) = a[i..][0..32].*;
        const vb: @Vector(32, u8) = b[i..][0..32].*;
        res[i..][0..32].* = va | vb;
    }
}

pub fn v_xor(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    const len = v_len(inst);

    const a = vm.vregs[a_idx];
    const b = vm.vregs[b_idx];
    if (a.len < len or b.len < len) return error.VectorTooSmall;

    const res = try ensureCapacity(vm, rd_idx, len);
    var i: usize = 0;
    while (i < len) : (i += 32) {
        const va: @Vector(32, u8) = a[i..][0..32].*;
        const vb: @Vector(32, u8) = b[i..][0..32].*;
        res[i..][0..32].* = va ^ vb;
    }
}

pub fn v_iadds(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const v_idx = rs1(inst);
    const s_idx = rs2(inst);
    const len = v_len(inst);

    const v = vm.vregs[v_idx];
    const s: u8 = @intCast(vm.regs[s_idx] & 0xFF);
    if (v.len < len) return error.VectorTooSmall;

    const res = try ensureCapacity(vm, rd_idx, len);
    var i: usize = 0;
    const vs: @Vector(32, u8) = @splat(s);
    while (i < len) : (i += 32) {
        const va: @Vector(32, u8) = v[i..][0..32].*;
        res[i..][0..32].* = va +% vs;
    }
}

pub fn v_isubs(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const v_idx = rs1(inst);
    const s_idx = rs2(inst);
    const len = v_len(inst);

    const v = vm.vregs[v_idx];
    const s: u8 = @intCast(vm.regs[s_idx] & 0xFF);
    if (v.len < len) return error.VectorTooSmall;

    const res = try ensureCapacity(vm, rd_idx, len);
    var i: usize = 0;
    const vs: @Vector(32, u8) = @splat(s);
    while (i < len) : (i += 32) {
        const va: @Vector(32, u8) = v[i..][0..32].*;
        res[i..][0..32].* = va -% vs;
    }
}

pub fn v_imuls(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const v_idx = rs1(inst);
    const s_idx = rs2(inst);
    const len = v_len(inst);

    const v = vm.vregs[v_idx];
    const s: u8 = @intCast(vm.regs[s_idx] & 0xFF);
    if (v.len < len) return error.VectorTooSmall;

    const res = try ensureCapacity(vm, rd_idx, len);
    var i: usize = 0;
    const vs: @Vector(32, u8) = @splat(s);
    while (i < len) : (i += 32) {
        const va: @Vector(32, u8) = v[i..][0..32].*;
        res[i..][0..32].* = va *% vs;
    }
}

pub fn v_fadd(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    const len = v_len(inst);
    const float_count = len / 8;

    const a = vm.vregs[a_idx];
    const b = vm.vregs[b_idx];
    if (a.len < len or b.len < len) return error.VectorTooSmall;

    const res = try ensureCapacity(vm, rd_idx, len);
    var i: usize = 0;
    while (i < float_count) : (i += 4) {
        const va: @Vector(4, f64) = .{
            @bitCast(std.mem.readInt(u64, a[(i + 0) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, a[(i + 1) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, a[(i + 2) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, a[(i + 3) * 8 ..][0..8], .big)),
        };
        const vb: @Vector(4, f64) = .{
            @bitCast(std.mem.readInt(u64, b[(i + 0) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, b[(i + 1) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, b[(i + 2) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, b[(i + 3) * 8 ..][0..8], .big)),
        };
        const vr = va + vb;
        std.mem.writeInt(u64, res[(i + 0) * 8 ..][0..8], @bitCast(vr[0]), .big);
        std.mem.writeInt(u64, res[(i + 1) * 8 ..][0..8], @bitCast(vr[1]), .big);
        std.mem.writeInt(u64, res[(i + 2) * 8 ..][0..8], @bitCast(vr[2]), .big);
        std.mem.writeInt(u64, res[(i + 3) * 8 ..][0..8], @bitCast(vr[3]), .big);
    }
}

pub fn v_fsub(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    const len = v_len(inst);
    const float_count = len / 8;

    const a = vm.vregs[a_idx];
    const b = vm.vregs[b_idx];
    if (a.len < len or b.len < len) return error.VectorTooSmall;

    const res = try ensureCapacity(vm, rd_idx, len);
    var i: usize = 0;
    while (i < float_count) : (i += 4) {
        const va: @Vector(4, f64) = .{
            @bitCast(std.mem.readInt(u64, a[(i + 0) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, a[(i + 1) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, a[(i + 2) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, a[(i + 3) * 8 ..][0..8], .big)),
        };
        const vb: @Vector(4, f64) = .{
            @bitCast(std.mem.readInt(u64, b[(i + 0) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, b[(i + 1) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, b[(i + 2) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, b[(i + 3) * 8 ..][0..8], .big)),
        };
        const vr = va - vb;
        std.mem.writeInt(u64, res[(i + 0) * 8 ..][0..8], @bitCast(vr[0]), .big);
        std.mem.writeInt(u64, res[(i + 1) * 8 ..][0..8], @bitCast(vr[1]), .big);
        std.mem.writeInt(u64, res[(i + 2) * 8 ..][0..8], @bitCast(vr[2]), .big);
        std.mem.writeInt(u64, res[(i + 3) * 8 ..][0..8], @bitCast(vr[3]), .big);
    }
}

pub fn v_fmul(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    const len = v_len(inst);
    const float_count = len / 8;

    const a = vm.vregs[a_idx];
    const b = vm.vregs[b_idx];
    if (a.len < len or b.len < len) return error.VectorTooSmall;

    const res = try ensureCapacity(vm, rd_idx, len);
    var i: usize = 0;
    while (i < float_count) : (i += 4) {
        const va: @Vector(4, f64) = .{
            @bitCast(std.mem.readInt(u64, a[(i + 0) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, a[(i + 1) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, a[(i + 2) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, a[(i + 3) * 8 ..][0..8], .big)),
        };
        const vb: @Vector(4, f64) = .{
            @bitCast(std.mem.readInt(u64, b[(i + 0) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, b[(i + 1) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, b[(i + 2) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, b[(i + 3) * 8 ..][0..8], .big)),
        };
        const vr = va * vb;
        std.mem.writeInt(u64, res[(i + 0) * 8 ..][0..8], @bitCast(vr[0]), .big);
        std.mem.writeInt(u64, res[(i + 1) * 8 ..][0..8], @bitCast(vr[1]), .big);
        std.mem.writeInt(u64, res[(i + 2) * 8 ..][0..8], @bitCast(vr[2]), .big);
        std.mem.writeInt(u64, res[(i + 3) * 8 ..][0..8], @bitCast(vr[3]), .big);
    }
}

pub fn v_fdiv(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    const len = v_len(inst);
    const float_count = len / 8;

    const a = vm.vregs[a_idx];
    const b = vm.vregs[b_idx];
    if (a.len < len or b.len < len) return error.VectorTooSmall;

    const res = try ensureCapacity(vm, rd_idx, len);
    var i: usize = 0;
    while (i < float_count) : (i += 4) {
        const va: @Vector(4, f64) = .{
            @bitCast(std.mem.readInt(u64, a[(i + 0) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, a[(i + 1) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, a[(i + 2) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, a[(i + 3) * 8 ..][0..8], .big)),
        };
        const vb: @Vector(4, f64) = .{
            @bitCast(std.mem.readInt(u64, b[(i + 0) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, b[(i + 1) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, b[(i + 2) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, b[(i + 3) * 8 ..][0..8], .big)),
        };
        const vr = va / vb;
        std.mem.writeInt(u64, res[(i + 0) * 8 ..][0..8], @bitCast(vr[0]), .big);
        std.mem.writeInt(u64, res[(i + 1) * 8 ..][0..8], @bitCast(vr[1]), .big);
        std.mem.writeInt(u64, res[(i + 2) * 8 ..][0..8], @bitCast(vr[2]), .big);
        std.mem.writeInt(u64, res[(i + 3) * 8 ..][0..8], @bitCast(vr[3]), .big);
    }
}

pub fn v_fsqrt(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const len = v_len(inst);
    const float_count = len / 8;

    const a = vm.vregs[a_idx];
    if (a.len < len) return error.VectorTooSmall;

    const res = try ensureCapacity(vm, rd_idx, len);
    var i: usize = 0;
    while (i < float_count) : (i += 4) {
        const va: @Vector(4, f64) = .{
            @bitCast(std.mem.readInt(u64, a[(i + 0) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, a[(i + 1) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, a[(i + 2) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, a[(i + 3) * 8 ..][0..8], .big)),
        };
        const vr = @sqrt(va);
        std.mem.writeInt(u64, res[(i + 0) * 8 ..][0..8], @bitCast(vr[0]), .big);
        std.mem.writeInt(u64, res[(i + 1) * 8 ..][0..8], @bitCast(vr[1]), .big);
        std.mem.writeInt(u64, res[(i + 2) * 8 ..][0..8], @bitCast(vr[2]), .big);
        std.mem.writeInt(u64, res[(i + 3) * 8 ..][0..8], @bitCast(vr[3]), .big);
    }
}

pub fn v_splat(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const rs_idx = rs1(inst);
    const len = v_len(inst);
    const float_count = len / 8;
    const val: u64 = vm.regs[rs_idx];

    const res = try ensureCapacity(vm, rd_idx, len);
    var i: usize = 0;
    const val_be = std.mem.nativeToBig(u64, val);
    while (i < float_count) : (i += 4) {
        const v: @Vector(4, u64) = @splat(val_be);
        res[i * 8 ..][0..32].* = @bitCast(v);
    }
}

pub fn v_fadds(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const v_idx = rs1(inst);
    const s_idx = rs2(inst);
    const len = v_len(inst);
    const float_count = len / 8;
    const s: f64 = @bitCast(vm.regs[s_idx]);

    const v = vm.vregs[v_idx];
    if (v.len < len) return error.VectorTooSmall;

    const res = try ensureCapacity(vm, rd_idx, len);
    var i: usize = 0;
    while (i < float_count) : (i += 4) {
        const va: @Vector(4, f64) = .{
            @bitCast(std.mem.readInt(u64, v[(i + 0) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, v[(i + 1) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, v[(i + 2) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, v[(i + 3) * 8 ..][0..8], .big)),
        };
        const vs: @Vector(4, f64) = @splat(s);
        const vr = va + vs;
        std.mem.writeInt(u64, res[(i + 0) * 8 ..][0..8], @bitCast(vr[0]), .big);
        std.mem.writeInt(u64, res[(i + 1) * 8 ..][0..8], @bitCast(vr[1]), .big);
        std.mem.writeInt(u64, res[(i + 2) * 8 ..][0..8], @bitCast(vr[2]), .big);
        std.mem.writeInt(u64, res[(i + 3) * 8 ..][0..8], @bitCast(vr[3]), .big);
    }
}

pub fn v_fsubs(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const v_idx = rs1(inst);
    const s_idx = rs2(inst);
    const len = v_len(inst);
    const float_count = len / 8;
    const s: f64 = @bitCast(vm.regs[s_idx]);

    const v = vm.vregs[v_idx];
    if (v.len < len) return error.VectorTooSmall;

    const res = try ensureCapacity(vm, rd_idx, len);
    var i: usize = 0;
    while (i < float_count) : (i += 4) {
        const va: @Vector(4, f64) = .{
            @bitCast(std.mem.readInt(u64, v[(i + 0) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, v[(i + 1) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, v[(i + 2) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, v[(i + 3) * 8 ..][0..8], .big)),
        };
        const vs: @Vector(4, f64) = @splat(s);
        const vr = va - vs;
        std.mem.writeInt(u64, res[(i + 0) * 8 ..][0..8], @bitCast(vr[0]), .big);
        std.mem.writeInt(u64, res[(i + 1) * 8 ..][0..8], @bitCast(vr[1]), .big);
        std.mem.writeInt(u64, res[(i + 2) * 8 ..][0..8], @bitCast(vr[2]), .big);
        std.mem.writeInt(u64, res[(i + 3) * 8 ..][0..8], @bitCast(vr[3]), .big);
    }
}

pub fn v_fmuls(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const v_idx = rs1(inst);
    const s_idx = rs2(inst);
    const len = v_len(inst);
    const float_count = len / 8;
    const s: f64 = @bitCast(vm.regs[s_idx]);

    const v = vm.vregs[v_idx];
    if (v.len < len) return error.VectorTooSmall;

    const res = try ensureCapacity(vm, rd_idx, len);
    var i: usize = 0;
    while (i < float_count) : (i += 4) {
        const va: @Vector(4, f64) = .{
            @bitCast(std.mem.readInt(u64, v[(i + 0) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, v[(i + 1) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, v[(i + 2) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, v[(i + 3) * 8 ..][0..8], .big)),
        };
        const vs: @Vector(4, f64) = @splat(s);
        const vr = va * vs;
        std.mem.writeInt(u64, res[(i + 0) * 8 ..][0..8], @bitCast(vr[0]), .big);
        std.mem.writeInt(u64, res[(i + 1) * 8 ..][0..8], @bitCast(vr[1]), .big);
        std.mem.writeInt(u64, res[(i + 2) * 8 ..][0..8], @bitCast(vr[2]), .big);
        std.mem.writeInt(u64, res[(i + 3) * 8 ..][0..8], @bitCast(vr[3]), .big);
    }
}

pub fn v_fdivs(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const v_idx = rs1(inst);
    const s_idx = rs2(inst);
    const len = v_len(inst);
    const float_count = len / 8;
    const s: f64 = @bitCast(vm.regs[s_idx]);

    const v = vm.vregs[v_idx];
    if (v.len < len) return error.VectorTooSmall;

    const res = try ensureCapacity(vm, rd_idx, len);
    var i: usize = 0;
    while (i < float_count) : (i += 4) {
        const va: @Vector(4, f64) = .{
            @bitCast(std.mem.readInt(u64, v[(i + 0) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, v[(i + 1) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, v[(i + 2) * 8 ..][0..8], .big)),
            @bitCast(std.mem.readInt(u64, v[(i + 3) * 8 ..][0..8], .big)),
        };
        const vs: @Vector(4, f64) = @splat(s);
        const vr = va / vs;
        std.mem.writeInt(u64, res[(i + 0) * 8 ..][0..8], @bitCast(vr[0]), .big);
        std.mem.writeInt(u64, res[(i + 1) * 8 ..][0..8], @bitCast(vr[1]), .big);
        std.mem.writeInt(u64, res[(i + 2) * 8 ..][0..8], @bitCast(vr[2]), .big);
        std.mem.writeInt(u64, res[(i + 3) * 8 ..][0..8], @bitCast(vr[3]), .big);
    }
}

pub fn v_shuffle(vm: *VM, inst: u64) !void {
    const rd_idx = rd(inst);
    const a_idx = rs1(inst);
    const b_idx = rs2(inst);
    const len = v_len(inst);

    const a = vm.vregs[a_idx];
    const b = vm.vregs[b_idx];
    if (a.len < len or b.len < len) return error.VectorTooSmall;

    const res = try ensureCapacity(vm, rd_idx, len);
    var i: usize = 0;
    while (i < len) : (i += 32) {
        const va: @Vector(32, u8) = a[i..][0..32].*;
        const vb: @Vector(32, u8) = b[i..][0..32].*;
        res[i..][0..32].* = va ^ vb;
    }
}
