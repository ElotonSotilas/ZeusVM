const std = @import("std");
const ZeusVM = @import("../root.zig");
const Opcode = ZeusVM.opcode.Opcode;
pub const Jit = @import("jit.zig").Jit;

const s1 = @import("handlers/s1.zig");
const s2 = @import("handlers/s2.zig");
const s3 = @import("handlers/s3.zig");
const s4 = @import("handlers/s4.zig");
const s5 = @import("handlers/s5.zig");
const s6 = @import("handlers/s6.zig");
const s7 = @import("handlers/s7.zig");
const s8 = @import("handlers/s8.zig");
const s9 = @import("handlers/s9.zig");
const s10 = @import("handlers/s10.zig");

pub const Handler = *const fn (vm: *VM, inst: u64) anyerror!void;

pub const VMError = enum {
    OutOfBoundsPC,
    UnknownOpcode,
};

pub const VM = struct {
    regs: [256]u64,
    vregs: [256][]u8,
    vreg_caps: [256]u32,
    pc: usize,
    memory: []u8,
    stack: [1024]u64,
    sp: usize,
    running: bool,
    host: ZeusVM.bootstrap.Host,

    /// Queue of async tasks
    tasks: std.ArrayList(*std.Thread) = .{},

    /// Dispatch table
    dispatch: [256]?Handler = [_]?Handler{null} ** 256,

    /// JIT state
    jit: ?*Jit = null,
    use_jit: bool = false,

    /// Helper for dynamic loading
    next_free_addr: usize = 0,

    pub fn deinit(self: *VM) void {
        for (self.vregs) |v| {
            if (v.len > 0) self.host.allocator.free(v);
        }
        self.tasks.deinit(self.host.allocator);
    }

    pub fn runAsync(self: *VM) !void {
        self.running = true;
        var prev_pc: usize = 0xFFFFFFFFFFFFFFFF;

        while (self.running) {
            const current_pc = self.pc;
            // 0. JIT Dispatch
            if (self.use_jit) {
                if (self.jit) |j| {
                    const is_loop = current_pc <= prev_pc;
                    if (j.cache.get(current_pc)) |func| {
                        func(self);
                        if (!self.running) break;
                        prev_pc = current_pc;
                        continue;
                    } else if (j.shouldCompile(current_pc, is_loop)) {
                        if (j.compileBlock(self, current_pc)) |func| {
                            func(self);
                            prev_pc = current_pc;
                            continue;
                        } else |_| {
                            j.failed_compilations.put(current_pc, {}) catch {};
                        }
                    }
                }
            }

            // 1. Fetch instruction
            if (self.pc + 8 > self.memory.len) return error.OutOfBoundsPC;
            const inst: u64 = std.mem.readInt(u64, self.memory[self.pc..][0..8], .big);
            const opcode: u8 = @intCast(inst >> 56);

            // 2. Dispatch instruction
            const handler = self.dispatch[opcode] orelse return error.UnknownOpcode;

            // 3. Call handler; if it’s async, it can return NotReady
            handler(self, inst) catch |err| {
                if (err == error.NotReady) {
                    // Yield and continue loop
                    if (self.host.threading) |threading| {
                        threading.yield(threading.ctx);
                    }
                    self.pc = current_pc; // stay at same instruction
                    continue;
                } else {
                    return err;
                }
            };

            // 4. Capture current PC as prev_pc but ensure we see the branch result
            prev_pc = current_pc;

            // 5. Advance PC for normal instructions
            // (Note: Control flow handlers might have already updated self.pc)
            if (self.pc == current_pc) {
                self.pc += 8;
            }
        }
    }
};

/// Initialize a new VM instance
pub fn init(host: ZeusVM.bootstrap.Host, memory: []u8) VM {
    var vm = VM{
        .regs = [_]u64{0} ** 256,
        .vregs = [_][]u8{""} ** 256,
        .vreg_caps = [_]u32{0} ** 256,
        .pc = 0,
        .memory = memory,
        .stack = undefined,
        .sp = 0,
        .running = false,
        .host = host,
        .dispatch = [_]?Handler{null} ** 256,
        .next_free_addr = 0,
    };

    //=============================
    // Core control instructions
    //=============================
    vm.dispatch[@intFromEnum(Opcode.NOP)] = s1.nop;
    vm.dispatch[@intFromEnum(Opcode.HALT)] = s1.halt;
    vm.dispatch[@intFromEnum(Opcode.JMP)] = s1.jmp;
    vm.dispatch[@intFromEnum(Opcode.BR)] = s1.br;
    vm.dispatch[@intFromEnum(Opcode.BR_IF)] = s1.br_if;
    vm.dispatch[@intFromEnum(Opcode.CALL)] = s1.call;
    vm.dispatch[@intFromEnum(Opcode.CALL_REG)] = s1.call_reg;
    vm.dispatch[@intFromEnum(Opcode.RET)] = s1.ret;

    //=============================
    // Integer arithmetic
    //=============================
    vm.dispatch[@intFromEnum(Opcode.IADD)] = s2.iadd;
    vm.dispatch[@intFromEnum(Opcode.ISUB)] = s2.isub;
    vm.dispatch[@intFromEnum(Opcode.IMUL)] = s2.imul;
    vm.dispatch[@intFromEnum(Opcode.IDIV)] = s2.idiv;
    vm.dispatch[@intFromEnum(Opcode.IMOD)] = s2.imod;
    vm.dispatch[@intFromEnum(Opcode.IAND)] = s2.iand;
    vm.dispatch[@intFromEnum(Opcode.IOR)] = s2.ior;
    vm.dispatch[@intFromEnum(Opcode.IXOR)] = s2.ixor;
    vm.dispatch[@intFromEnum(Opcode.ISHL)] = s2.ishl;
    vm.dispatch[@intFromEnum(Opcode.ISHR)] = s2.ishr;

    //=============================
    // Memory / Heap / Pointer
    //=============================
    vm.dispatch[@intFromEnum(Opcode.LOAD)] = s3.load;
    vm.dispatch[@intFromEnum(Opcode.STORE)] = s3.store;
    vm.dispatch[@intFromEnum(Opcode.MEM_COPY)] = s3.mem_copy;
    vm.dispatch[@intFromEnum(Opcode.MEM_ZERO)] = s3.mem_zero;
    vm.dispatch[@intFromEnum(Opcode.HEAP_ALLOC)] = s3.heap_alloc;
    vm.dispatch[@intFromEnum(Opcode.HEAP_FREE)] = s3.heap_free;
    vm.dispatch[@intFromEnum(Opcode.PTR_ADD)] = s3.ptr_add;
    vm.dispatch[@intFromEnum(Opcode.PTR_SUB)] = s3.ptr_sub;

    //=============================
    // Comparisons
    //=============================
    vm.dispatch[@intFromEnum(Opcode.ICMP_EQ)] = s4.icmp_eq;
    vm.dispatch[@intFromEnum(Opcode.ICMP_NE)] = s4.icmp_ne;
    vm.dispatch[@intFromEnum(Opcode.ICMP_LT)] = s4.icmp_lt;
    vm.dispatch[@intFromEnum(Opcode.ICMP_GT)] = s4.icmp_gt;
    vm.dispatch[@intFromEnum(Opcode.ICMP_LE)] = s4.icmp_le;
    vm.dispatch[@intFromEnum(Opcode.ICMP_GE)] = s4.icmp_ge;

    //=============================
    // Time & Threads
    //=============================
    vm.dispatch[@intFromEnum(Opcode.TIME_NOW)] = s5.time_now;
    vm.dispatch[@intFromEnum(Opcode.SLEEP_NS)] = s5.sleep_ns;
    vm.dispatch[@intFromEnum(Opcode.THREAD_SPAWN)] = s5.thread_spawn;
    vm.dispatch[@intFromEnum(Opcode.THREAD_JOIN)] = s5.thread_join;
    vm.dispatch[@intFromEnum(Opcode.THREAD_YIELD)] = s5.thread_yield;

    //=============================
    // Filesystem
    //=============================
    vm.dispatch[@intFromEnum(Opcode.FS_OPEN)] = s8.fs_open;
    vm.dispatch[@intFromEnum(Opcode.FS_READ)] = s8.fs_read;
    vm.dispatch[@intFromEnum(Opcode.FS_WRITE)] = s8.fs_write;
    vm.dispatch[@intFromEnum(Opcode.FS_CLOSE)] = s8.fs_close;
    vm.dispatch[@intFromEnum(Opcode.FS_SIZE)] = s8.fs_size;
    vm.dispatch[@intFromEnum(Opcode.FS_SEEK)] = s8.fs_seek;
    vm.dispatch[@intFromEnum(Opcode.FS_MKDIR)] = s8.fs_mkdir;
    vm.dispatch[@intFromEnum(Opcode.FS_REMOVE)] = s8.fs_remove;

    vm.dispatch[@intFromEnum(Opcode.LOAD_MODULE)] = s8.load_module;
    vm.dispatch[@intFromEnum(Opcode.STDIN_READ)] = s8.stdin_read;
    vm.dispatch[@intFromEnum(Opcode.STDOUT_WRITE)] = s8.stdout_write;
    vm.dispatch[@intFromEnum(Opcode.STDERR_WRITE)] = s8.stderr_write;

    //=============================
    // Networking
    //=============================
    vm.dispatch[@intFromEnum(Opcode.NET_OPEN)] = s6.net_open;
    vm.dispatch[@intFromEnum(Opcode.NET_CLOSE)] = s6.net_close;
    vm.dispatch[@intFromEnum(Opcode.NET_SEND)] = s6.net_send;
    vm.dispatch[@intFromEnum(Opcode.NET_RECV)] = s6.net_recv;
    vm.dispatch[@intFromEnum(Opcode.NET_POLL)] = s6.net_poll;
    vm.dispatch[@intFromEnum(Opcode.NET_LISTEN)] = s6.net_listen;
    vm.dispatch[@intFromEnum(Opcode.NET_ACCEPT)] = s6.net_accept;

    //=============================
    // Dynamic Vectors
    //=============================
    const vd = @import("handlers/v_dynamic.zig");
    vm.dispatch[@intFromEnum(Opcode.V_LOAD)] = vd.v_load;
    vm.dispatch[@intFromEnum(Opcode.V_STORE)] = vd.v_store;
    vm.dispatch[@intFromEnum(Opcode.V_ADD)] = vd.v_add;
    vm.dispatch[@intFromEnum(Opcode.V_SUB)] = vd.v_sub;
    vm.dispatch[@intFromEnum(Opcode.V_MUL)] = vd.v_mul;
    vm.dispatch[@intFromEnum(Opcode.V_AND)] = vd.v_and;
    vm.dispatch[@intFromEnum(Opcode.V_OR)] = vd.v_or;
    vm.dispatch[@intFromEnum(Opcode.V_XOR)] = vd.v_xor;
    vm.dispatch[@intFromEnum(Opcode.V_FADD)] = vd.v_fadd;
    vm.dispatch[@intFromEnum(Opcode.V_FSUB)] = vd.v_fsub;
    vm.dispatch[@intFromEnum(Opcode.V_FMUL)] = vd.v_fmul;
    vm.dispatch[@intFromEnum(Opcode.V_FDIV)] = vd.v_fdiv;
    vm.dispatch[@intFromEnum(Opcode.V_FSQRT)] = vd.v_fsqrt;
    vm.dispatch[@intFromEnum(Opcode.V_SPLAT)] = vd.v_splat;
    vm.dispatch[@intFromEnum(Opcode.V_SHUFFLE)] = vd.v_shuffle;

    //=============================
    // Atomics
    //=============================
    vm.dispatch[@intFromEnum(Opcode.ATOMIC_LOAD)] = s9.atomic_load;
    vm.dispatch[@intFromEnum(Opcode.ATOMIC_STORE)] = s9.atomic_store;
    vm.dispatch[@intFromEnum(Opcode.ATOMIC_RMW)] = s9.atomic_rmw;
    vm.dispatch[@intFromEnum(Opcode.ATOMIC_CAS)] = s9.atomic_cas;

    //=============================
    // Floating Point (F64)
    //=============================
    vm.dispatch[@intFromEnum(Opcode.FADD)] = s10.fadd;
    vm.dispatch[@intFromEnum(Opcode.FSUB)] = s10.fsub;
    vm.dispatch[@intFromEnum(Opcode.FMUL)] = s10.fmul;
    vm.dispatch[@intFromEnum(Opcode.FDIV)] = s10.fdiv;
    vm.dispatch[@intFromEnum(Opcode.FNEG)] = s10.fneg;
    vm.dispatch[@intFromEnum(Opcode.FABS)] = s10.fabs;
    vm.dispatch[@intFromEnum(Opcode.FSQRT)] = s10.fsqrt;

    vm.dispatch[@intFromEnum(Opcode.FCMP_EQ)] = s10.fcmp_eq;
    vm.dispatch[@intFromEnum(Opcode.FCMP_NE)] = s10.fcmp_ne;
    vm.dispatch[@intFromEnum(Opcode.FCMP_LT)] = s10.fcmp_lt;
    vm.dispatch[@intFromEnum(Opcode.FCMP_GT)] = s10.fcmp_gt;
    vm.dispatch[@intFromEnum(Opcode.FCMP_LE)] = s10.fcmp_le;
    vm.dispatch[@intFromEnum(Opcode.FCMP_GE)] = s10.fcmp_ge;

    vm.dispatch[@intFromEnum(Opcode.FCONV_I2F)] = s10.fconv_i2f;
    vm.dispatch[@intFromEnum(Opcode.FCONV_F2I)] = s10.fconv_f2i;

    //=============================
    // Dynamic Library (FFI)
    //=============================
    vm.dispatch[@intFromEnum(Opcode.DL_OPEN)] = s7.dl_open;
    vm.dispatch[@intFromEnum(Opcode.DL_SYM)] = s7.dl_sym;
    vm.dispatch[@intFromEnum(Opcode.DL_CALL)] = s7.dl_call;
    vm.dispatch[@intFromEnum(Opcode.DL_CLOSE)] = s7.dl_close;

    return vm;
}
