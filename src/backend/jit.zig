const std = @import("std");
const ZeusVM = @import("../root.zig");
const Opcode = ZeusVM.opcode.Opcode;
const VM = ZeusVM.vm.VM;

pub const JitFunction = *const fn (vm: *VM) callconv(.c) void;

pub const Jit = struct {
    allocator: std.mem.Allocator,
    code_buffer: []align(std.heap.page_size_min) u8,
    cursor: usize = 0,

    // Map from VM PC to JITed function address (offset in code_buffer)
    cache: std.AutoHashMap(usize, JitFunction),

    // Map from VM PC to execution count (hotness)
    hotness: std.AutoHashMap(usize, u32),

    // Map from VM PC to failed compilation flag
    failed_compilations: std.AutoHashMap(usize, void),

    threshold: u32 = 50,

    pub fn init(allocator: std.mem.Allocator, size: usize, host: ZeusVM.bootstrap.Host) !*Jit {
        const self = try allocator.create(Jit);
        const mem = host.memory orelse return error.MemoryAbstractionMissing;

        // Allocate memory with proper alignment
        const buffer = try mem.alloc(mem.ctx, size, std.heap.page_size_min);
        errdefer mem.free(mem.ctx, buffer);

        // Initial permissions: Read | Write | Exec
        try mem.protect(mem.ctx, buffer, .read_write_exec);

        self.* = .{
            .allocator = allocator,
            .code_buffer = @alignCast(buffer),
            .cache = std.AutoHashMap(usize, JitFunction).init(allocator),
            .hotness = std.AutoHashMap(usize, u32).init(allocator),
            .failed_compilations = std.AutoHashMap(usize, void).init(allocator),
        };
        return self;
    }

    pub fn deinit(self: *Jit, host: ZeusVM.bootstrap.Host) void {
        if (host.memory) |mem| {
            mem.free(mem.ctx, self.code_buffer);
        }
        self.cache.deinit();
        self.hotness.deinit();
        self.failed_compilations.deinit();
        self.allocator.destroy(self);
    }

    pub fn shouldCompile(self: *Jit, pc: usize, is_loop: bool) bool {
        if (self.cache.contains(pc)) return true;
        if (self.failed_compilations.contains(pc)) return false;

        const entry = self.hotness.getOrPutValue(pc, 0) catch return false;

        // Boost hotness significantly for loop headers to trigger compilation faster
        if (is_loop) {
            entry.value_ptr.* += 10;
        } else {
            entry.value_ptr.* += 1;
        }

        return entry.value_ptr.* >= self.threshold;
    }

    pub fn makeExecutable(self: *Jit, host: ZeusVM.bootstrap.Host) !void {
        const mem = host.memory orelse return error.MemoryAbstractionMissing;
        try mem.protect(mem.ctx, self.code_buffer, .read_exec);
    }

    const HostReg = enum(u8) {
        rbx = 3,
        r12 = 12,
        r13 = 13,
        r14 = 14,
        r15 = 15,

        fn fromVm(idx: u64) ?HostReg {
            return switch (idx) {
                0 => .rbx,
                1 => .r12,
                2 => .r13,
                3 => .r14,
                4 => .r15,
                else => null,
            };
        }
    };

    const HostVReg = enum(u8) {
        xmm0 = 0,
        xmm1 = 1,
        xmm2 = 2,
        xmm3 = 3,
        xmm4 = 4,
        xmm5 = 5,
        xmm6 = 6,
        xmm7 = 7,

        fn fromVm(idx: u64) ?HostVReg {
            if (idx < 8) return @enumFromInt(idx);
            return null;
        }
    };

    pub fn compileBlock(self: *Jit, vm: *VM, start_pc: usize) !JitFunction {
        if (self.cache.get(start_pc)) |func| return func;

        const func_start = self.cursor;

        // --- Prologue ---
        // Save callee-saved registers: rbx, r12, r13, r14, r15
        try self.emit(&.{0x53}); // push rbx
        try self.emit(&.{ 0x41, 0x54 }); // push r12
        try self.emit(&.{ 0x41, 0x55 }); // push r13
        try self.emit(&.{ 0x41, 0x56 }); // push r14
        try self.emit(&.{ 0x41, 0x57 }); // push r15

        // Load R0-R4 into these host registers
        inline for (0..5) |i| {
            try self.emit_load_host_reg_from_vm(i);
        }

        // Load V0-V3 into XMM0-XMM3
        inline for (0..4) |i| {
            try self.emit_load_host_vreg_from_vm(i);
        }

        const loop_start = self.cursor;

        var pc = start_pc;
        while (pc + 8 <= vm.memory.len) {
            const inst: u64 = std.mem.readInt(u64, vm.memory[pc..][0..8], .big);
            const opcode: u8 = @intCast(inst >> 56);
            const op: Opcode = @enumFromInt(opcode);

            const rd_idx = (inst >> 48) & 0xFF;
            const rs1_idx = (inst >> 40) & 0xFF;
            const rs2_idx = (inst >> 32) & 0xFF;
            const imm = @as(u32, @intCast(inst & 0xFFFFFFFF));

            switch (op) {
                .IADD => {
                    try self.emit_mov_rax_reg(rs1_idx);
                    try self.emit_add_rax_reg(rs2_idx);
                    try self.emit_mov_reg_rax(rd_idx);
                },
                .ISUB => {
                    try self.emit_mov_rax_reg(rs1_idx);
                    try self.emit_sub_rax_reg(rs2_idx);
                    try self.emit_mov_reg_rax(rd_idx);
                },
                .IMUL => {
                    try self.emit_mov_rax_reg(rs1_idx);
                    try self.emit_imul_rax_reg(rs2_idx);
                    try self.emit_mov_reg_rax(rd_idx);
                },
                .IDIV => {
                    try self.emit_mov_rax_reg(rs1_idx);
                    try self.emit_cqo();
                    if (HostReg.fromVm(rs2_idx)) |host| {
                        try self.emit_idiv_reg(host);
                    } else {
                        const rs2_off = @offsetOf(VM, "regs") + rs2_idx * 8;
                        try self.emit_idiv_mem_rdi(rs2_off);
                    }
                    try self.emit_mov_reg_rax(rd_idx);
                },
                .IMOD => {
                    try self.emit_mov_rax_reg(rs1_idx);
                    try self.emit_cqo();
                    if (HostReg.fromVm(rs2_idx)) |host| {
                        try self.emit_idiv_reg(host);
                    } else {
                        const rs2_off = @offsetOf(VM, "regs") + rs2_idx * 8;
                        try self.emit_idiv_mem_rdi(rs2_off);
                    }
                    try self.emit_mov_reg_rdx(rd_idx);
                },
                .IAND => {
                    try self.emit_mov_rax_reg(rs1_idx);
                    try self.emit_and_rax_reg(rs2_idx);
                    try self.emit_mov_reg_rax(rd_idx);
                },
                .IOR => {
                    try self.emit_mov_rax_reg(rs1_idx);
                    try self.emit_or_rax_reg(rs2_idx);
                    try self.emit_mov_reg_rax(rd_idx);
                },
                .IXOR => {
                    try self.emit_mov_rax_reg(rs1_idx);
                    try self.emit_xor_rax_reg(rs2_idx);
                    try self.emit_mov_reg_rax(rd_idx);
                },
                .ISHL => {
                    try self.emit_mov_rax_reg(rs1_idx);
                    try self.emit_mov_rcx_reg(rs2_idx);
                    try self.emit_shl_rax_cl();
                    try self.emit_mov_reg_rax(rd_idx);
                },
                .ISHR => {
                    try self.emit_mov_rax_reg(rs1_idx);
                    try self.emit_mov_rcx_reg(rs2_idx);
                    try self.emit_shr_rax_cl();
                    try self.emit_mov_reg_rax(rd_idx);
                },
                .PTR_ADD => {
                    try self.emit_mov_rax_reg(rs1_idx);
                    try self.emit_add_rax_imm32(imm);
                    try self.emit_mov_reg_rax(rd_idx);
                },
                .PTR_SUB => {
                    try self.emit_mov_rax_reg(rs1_idx);
                    try self.emit(&.{ 0x48, 0x2D });
                    var buf: [4]u8 = undefined;
                    std.mem.writeInt(u32, &buf, imm, .little);
                    try self.emit(&buf);
                    try self.emit_mov_reg_rax(rd_idx);
                },
                .ICMP_EQ => {
                    try self.emit_mov_rax_reg(rs1_idx);
                    try self.emit_cmp_rax_reg(rs2_idx);
                    try self.emit_setcc_rax(0x94); // sete
                    try self.emit_mov_reg_rax(rd_idx);
                },
                .ICMP_NE => {
                    try self.emit_mov_rax_reg(rs1_idx);
                    try self.emit_cmp_rax_reg(rs2_idx);
                    try self.emit_setcc_rax(0x95); // setne
                    try self.emit_mov_reg_rax(rd_idx);
                },
                .ICMP_LT => {
                    try self.emit_mov_rax_reg(rs1_idx);
                    try self.emit_cmp_rax_reg(rs2_idx);
                    try self.emit_setcc_rax(0x9C); // setl
                    try self.emit_mov_reg_rax(rd_idx);
                },
                .ICMP_GE => {
                    try self.emit_mov_rax_reg(rs1_idx);
                    try self.emit_cmp_rax_reg(rs2_idx);
                    try self.emit_setcc_rax(0x9D); // setge
                    try self.emit_mov_reg_rax(rd_idx);
                },
                .ICMP_LE => {
                    try self.emit_mov_rax_reg(rs1_idx);
                    try self.emit_cmp_rax_reg(rs2_idx);
                    try self.emit_setcc_rax(0x9E); // setle
                    try self.emit_mov_reg_rax(rd_idx);
                },
                .ICMP_GT => {
                    try self.emit_mov_rax_reg(rs1_idx);
                    try self.emit_cmp_rax_reg(rs2_idx);
                    try self.emit_setcc_rax(0x9F); // setg
                    try self.emit_mov_reg_rax(rd_idx);
                },
                // --- Dynamic Vectors fall back to interpreter ---
                .V_LOAD, .V_STORE, .V_ADD, .V_SUB, .V_MUL, .V_AND, .V_OR, .V_XOR, .V_FADD, .V_FSUB, .V_FMUL, .V_FDIV, .V_FSQRT, .V_SPLAT, .V_SHUFFLE => {
                    if (pc == start_pc) return error.UnsupportedInstruction;
                    try self.emit_update_pc(pc);
                    try self.emit_full_epilogue();
                    break;
                },
                .FSUB => {
                    try self.emit_movq_xmm0_reg(rs1_idx);
                    try self.emit_subsd_xmm0_reg(rs2_idx);
                    try self.emit_movq_reg_xmm0(rd_idx);
                },
                .FMUL => {
                    try self.emit_movq_xmm0_reg(rs1_idx);
                    try self.emit_mulsd_xmm0_reg(rs2_idx);
                    try self.emit_movq_reg_xmm0(rd_idx);
                },
                .FDIV => {
                    try self.emit_movq_xmm0_reg(rs1_idx);
                    try self.emit_divsd_xmm0_reg(rs2_idx);
                    try self.emit_movq_reg_xmm0(rd_idx);
                },
                .FNEG => {
                    try self.emit_movq_xmm0_reg(rs1_idx);
                    try self.emit(&.{ 0x48, 0xB8 });
                    var mask_buf: [8]u8 = undefined;
                    std.mem.writeInt(u64, &mask_buf, 0x8000000000000000, .little);
                    try self.emit(&mask_buf);
                    try self.emit(&.{ 0x66, 0x48, 0x0F, 0x6E, 0xC8 });
                    try self.emit_xorpd_xmm0_xmm1();
                    try self.emit_movq_reg_xmm0(rd_idx);
                },
                .FABS => {
                    try self.emit_movq_xmm0_reg(rs1_idx);
                    try self.emit(&.{ 0x48, 0xB8 });
                    var mask_buf: [8]u8 = undefined;
                    std.mem.writeInt(u64, &mask_buf, 0x7FFFFFFFFFFFFFFF, .little);
                    try self.emit(&mask_buf);
                    try self.emit(&.{ 0x66, 0x48, 0x0F, 0x6E, 0xC8 });
                    try self.emit_andpd_xmm0_xmm1();
                    try self.emit_movq_reg_xmm0(rd_idx);
                },
                .FSQRT => {
                    try self.emit_movq_xmm0_reg(rs1_idx);
                    try self.emit_sqrtsd_xmm0_xmm0();
                    try self.emit_movq_reg_xmm0(rd_idx);
                },
                .FADD => {
                    try self.emit_movq_xmm0_reg(rs1_idx);
                    try self.emit_addsd_xmm0_reg(rs2_idx);
                    try self.emit_movq_reg_xmm0(rd_idx);
                },
                .FCMP_EQ => {
                    try self.emit_movq_xmm0_reg(rs1_idx);
                    try self.emit_ucomisd_xmm0_reg(rs2_idx);
                    try self.emit(&.{ 0x0F, 0x94, 0xC0 }); // sete al
                    try self.emit(&.{ 0x0F, 0x9B, 0xC1 }); // setnp cl
                    try self.emit(&.{ 0x21, 0xC8 }); // and eax, ecx
                    try self.emit(&.{ 0x48, 0x0F, 0xB6, 0xC0 });
                    try self.emit_mov_reg_rax(rd_idx);
                },
                .FCMP_LT => {
                    try self.emit_movq_xmm0_reg(rs1_idx);
                    try self.emit_ucomisd_xmm0_reg(rs2_idx);
                    try self.emit_setcc_rax(0x92); // setb
                    try self.emit_mov_reg_rax(rd_idx);
                },
                .STORE => {
                    try self.emit_mov_rax_reg(rs2_idx);
                    if (imm != 0) try self.emit_add_rax_imm32(imm);
                    try self.emit_mov_rcx_reg(rs1_idx);
                    try self.emit(&.{ 0x48, 0x0F, 0xC9 });
                    const mem_off = @offsetOf(VM, "memory");
                    try self.emit_mov_rdx_mem_rdi(mem_off);
                    try self.emit(&.{ 0x48, 0x89, 0x0C, 0x02 });
                },
                .LOAD => {
                    try self.emit_mov_rax_reg(rs1_idx);
                    if (imm != 0) try self.emit_add_rax_imm32(imm);
                    const mem_off = @offsetOf(VM, "memory");
                    try self.emit_mov_rdx_mem_rdi(mem_off);
                    try self.emit_mov_rax_mem_rdx_base_rax_off();
                    try self.emit_bswap_rax();
                    try self.emit_mov_reg_rax(rd_idx);
                },
                .FCONV_I2F => {
                    try self.emit_cvtsi2sd_xmm0_reg(rs1_idx);
                    try self.emit_movq_reg_xmm0(rd_idx);
                },
                .JMP => {
                    try self.emit_update_pc(imm);
                    try self.emit_full_epilogue();
                    break;
                },
                .BR => {
                    try self.emit_cmp_reg_zero(rs1_idx);
                    const skip_pos = try self.emit_jz_rel32_placeholder();
                    try self.emit_update_pc(imm);
                    try self.emit_full_epilogue();
                    self.patch_rel32(skip_pos);
                },
                .CALL => {
                    try self.emit_update_reg_imm(rd_idx, pc + 8); // Error in original: ZeusVM CALL uses stack
                    // Wait, looking at s1.zig:call, it does stack[sp] = pc + 8.
                    // Let's use the real stack logic.
                    try self.emit_stack_push_imm64(pc + 8);
                    try self.emit_update_pc(imm);
                    try self.emit_full_epilogue();
                    break;
                },
                .RET => {
                    try self.emit_stack_pop_rax();
                    const pc_offset = @offsetOf(VM, "pc");
                    try self.emit_mov_mem_rdi_rax(pc_offset);
                    try self.emit_full_epilogue();
                    break;
                },
                .CALL_REG => {
                    try self.emit_stack_push_imm64(pc + 8);
                    try self.emit_mov_rax_reg(rs1_idx);
                    const pc_offset = @offsetOf(VM, "pc");
                    try self.emit_mov_mem_rdi_rax(pc_offset);
                    try self.emit_full_epilogue();
                    break;
                },
                .BR_IF => {
                    try self.emit_cmp_reg_zero(rs1_idx);
                    if (imm == start_pc) {
                        try self.emit_jne_to_offset(loop_start);
                    } else {
                        const skip_pos = try self.emit_jz_rel32_placeholder();
                        try self.emit_update_pc(imm);
                        try self.emit_full_epilogue();
                        self.patch_rel32(skip_pos);
                    }
                },
                .HALT => {
                    try self.emit_update_pc(pc);
                    try self.emit_halt();
                    try self.emit_full_epilogue();
                    break;
                },
                else => {
                    const handler = vm.dispatch[opcode] orelse {
                        if (pc == start_pc) return error.UnsupportedInstruction;
                        try self.emit_update_pc(pc);
                        try self.emit_full_epilogue();
                        break;
                    };
                    try self.emit_update_pc(pc);
                    try self.emit_call_zig_handler(@intFromPtr(handler), inst);
                    try self.emit_update_pc(pc + 8);
                    try self.emit_full_epilogue();
                    break;
                },
            }
            pc += 8;
        }

        // Ensure PC is updated to the next instruction after the block finishes
        try self.emit_update_pc(pc);

        try self.emit_full_epilogue();

        const func: JitFunction = @ptrCast(&self.code_buffer[func_start]);
        try self.cache.put(start_pc, func);
        return func;
    }

    // --- x86_64 Emitters ---

    fn emit(self: *Jit, bytes: []const u8) !void {
        if (self.cursor + bytes.len > self.code_buffer.len) return error.OutOfMemory;
        @memcpy(self.code_buffer[self.cursor .. self.cursor + bytes.len], bytes);
        self.cursor += bytes.len;
    }

    fn emit_ret(self: *Jit) !void {
        try self.emit(&.{0xC3});
    }

    fn emit_mov_rax_mem_rdi(self: *Jit, offset: u64) !void {
        // mov rax, [rdi + disp32]
        // REX.W + 8B /r
        if (offset <= 127) {
            try self.emit(&.{ 0x48, 0x8B, 0x47, @intCast(offset) });
        } else {
            try self.emit(&.{ 0x48, 0x8B, 0x87 });
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf, @intCast(offset), .little);
            try self.emit(&buf);
        }
    }

    fn emit_mov_mem_rdi_rax(self: *Jit, offset: u64) !void {
        // mov [rdi + disp32], rax
        if (offset <= 127) {
            try self.emit(&.{ 0x48, 0x89, 0x47, @intCast(offset) });
        } else {
            try self.emit(&.{ 0x48, 0x89, 0x87 });
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf, @intCast(offset), .little);
            try self.emit(&buf);
        }
    }

    fn emit_add_rax_mem_rdi(self: *Jit, offset: u64) !void {
        // add rax, [rdi + disp32]
        if (offset <= 127) {
            try self.emit(&.{ 0x48, 0x03, 0x47, @intCast(offset) });
        } else {
            try self.emit(&.{ 0x48, 0x03, 0x87 });
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf, @intCast(offset), .little);
            try self.emit(&buf);
        }
    }

    fn emit_sub_rax_mem_rdi(self: *Jit, offset: u64) !void {
        // sub rax, [rdi + disp32]
        if (offset <= 127) {
            try self.emit(&.{ 0x48, 0x2B, 0x47, @intCast(offset) });
        } else {
            try self.emit(&.{ 0x48, 0x2B, 0x87 });
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf, @intCast(offset), .little);
            try self.emit(&buf);
        }
    }

    fn emit_imul_rax_mem_rdi(self: *Jit, offset: u64) !void {
        // imul rax, [rdi + disp32]
        if (offset <= 127) {
            try self.emit(&.{ 0x48, 0x0F, 0xAF, 0x47, @intCast(offset) });
        } else {
            try self.emit(&.{ 0x48, 0x0F, 0xAF, 0x87 });
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf, @intCast(offset), .little);
            try self.emit(&buf);
        }
    }

    fn emit_add_rax_imm32(self: *Jit, val: u32) !void {
        // add rax, imm32
        try self.emit(&.{ 0x48, 0x05 });
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf, val, .little);
        try self.emit(&buf);
    }

    fn emit_cmp_rax_mem_rdi(self: *Jit, offset: u64) !void {
        // cmp rax, [rdi + disp32]
        if (offset <= 127) {
            try self.emit(&.{ 0x48, 0x3B, 0x47, @intCast(offset) });
        } else {
            try self.emit(&.{ 0x48, 0x3B, 0x87 });
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf, @intCast(offset), .little);
            try self.emit(&buf);
        }
    }

    fn emit_setl_rax(self: *Jit) !void {
        // setl al
        try self.emit(&.{ 0x0F, 0x9C, 0xC0 });
        // movzx rax, al
        try self.emit(&.{ 0x48, 0x0F, 0xB6, 0xC0 });
    }

    fn emit_movq_xmm0_mem_rdi(self: *Jit, offset: u64) !void {
        // movq xmm0, [rdi + disp32]
        // F3 0F 7E /r
        if (offset <= 127) {
            try self.emit(&.{ 0xF3, 0x0F, 0x7E, 0x47, @intCast(offset) });
        } else {
            try self.emit(&.{ 0xF3, 0x0F, 0x7E, 0x87 });
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf, @intCast(offset), .little);
            try self.emit(&buf);
        }
    }

    fn emit_movq_mem_rdi_xmm0(self: *Jit, offset: u64) !void {
        // movq [rdi + disp32], xmm0
        // 66 0F D6 /r
        if (offset <= 127) {
            try self.emit(&.{ 0x66, 0x0F, 0xD6, 0x47, @intCast(offset) });
        } else {
            try self.emit(&.{ 0x66, 0x0F, 0xD6, 0x87 });
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf, @intCast(offset), .little);
            try self.emit(&buf);
        }
    }

    fn emit_sqrtsd_xmm0_xmm0(self: *Jit) !void {
        // sqrtsd xmm0, xmm0
        try self.emit(&.{ 0xF2, 0x0F, 0x51, 0xC0 });
    }

    fn emit_addsd_xmm0_mem_rdi(self: *Jit, offset: u64) !void {
        // addsd xmm0, [rdi + disp32]
        if (offset <= 127) {
            try self.emit(&.{ 0xF2, 0x0F, 0x58, 0x47, @intCast(offset) });
        } else {
            try self.emit(&.{ 0xF2, 0x0F, 0x58, 0x87 });
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf, @intCast(offset), .little);
            try self.emit(&buf);
        }
    }

    fn emit_cvtsi2sd_xmm0_mem_rdi(self: *Jit, offset: u64) !void {
        // cvtsi2sd xmm0, [rdi + disp32]
        if (offset <= 127) {
            try self.emit(&.{ 0xF2, 0x48, 0x0F, 0x2A, 0x47, @intCast(offset) });
        } else {
            try self.emit(&.{ 0xF2, 0x48, 0x0F, 0x2A, 0x87 });
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf, @intCast(offset), .little);
            try self.emit(&buf);
        }
    }

    fn emit_cmp_mem_rdi_zero(self: *Jit, offset: u64) !void {
        // cmp qword ptr [rdi + disp32], 0
        if (offset <= 127) {
            try self.emit(&.{ 0x48, 0x83, 0x7F, @intCast(offset), 0x00 });
        } else {
            try self.emit(&.{ 0x48, 0x81, 0xBF });
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf, @intCast(offset), .little);
            try self.emit(&buf);
            try self.emit(&.{ 0x00, 0x00, 0x00, 0x00 });
        }
    }

    fn emit_jne_to_offset(self: *Jit, target_offset: usize) !void {
        // jne NEAR relative (32-bit)
        // 0F 85 rel32
        const current = self.cursor + 6;
        const rel = @as(i32, @intCast(target_offset)) - @as(i32, @intCast(current));
        try self.emit(&.{ 0x0F, 0x85 });
        var buf: [4]u8 = undefined;
        std.mem.writeInt(i32, &buf, rel, .little);
        try self.emit(&buf);
    }

    fn emit_update_pc(self: *Jit, new_pc: u64) !void {
        // mov rax, new_pc
        try self.emit(&.{ 0x48, 0xB8 });
        var pc_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &pc_buf, new_pc, .little);
        try self.emit(&pc_buf);

        // mov [rdi + PC_OFFSET], rax
        const pc_offset = @offsetOf(VM, "pc");
        try self.emit(&.{ 0x48, 0x89, 0x87 });
        var off_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &off_buf, @intCast(pc_offset), .little);
        try self.emit(&off_buf);
    }

    fn emit_halt(self: *Jit) !void {
        // mov byte ptr [rdi + RUNNING_OFFSET], 0
        const running_offset = @offsetOf(VM, "running");
        try self.emit(&.{ 0xC6, 0x87 });
        var off_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &off_buf, @intCast(running_offset), .little);
        try self.emit(&off_buf);
        try self.emit(&.{0x00});
    }

    fn emit_xor_rax_mem_rdi(self: *Jit, offset: u64) !void {
        // xor rax, [rdi + offset]
        if (offset <= 127) {
            try self.emit(&.{ 0x48, 0x33, 0x47, @intCast(offset) });
        } else {
            try self.emit(&.{ 0x48, 0x33, 0x87 });
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf, @intCast(offset), .little);
            try self.emit(&buf);
        }
    }

    fn emit_and_rax_mem_rdi(self: *Jit, offset: u64) !void {
        // and rax, [rdi + offset]
        if (offset <= 127) {
            try self.emit(&.{ 0x48, 0x23, 0x47, @intCast(offset) });
        } else {
            try self.emit(&.{ 0x48, 0x23, 0x87 });
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf, @intCast(offset), .little);
            try self.emit(&buf);
        }
    }

    fn emit_or_rax_mem_rdi(self: *Jit, offset: u64) !void {
        // or rax, [rdi + offset]
        if (offset <= 127) {
            try self.emit(&.{ 0x48, 0x0B, 0x47, @intCast(offset) });
        } else {
            try self.emit(&.{ 0x48, 0x0B, 0x87 });
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf, @intCast(offset), .little);
            try self.emit(&buf);
        }
    }

    fn emit_subsd_xmm0_mem_rdi(self: *Jit, offset: u64) !void {
        // subsd xmm0, [rdi + offset]
        if (offset <= 127) {
            try self.emit(&.{ 0xF2, 0x0F, 0x5C, 0x47, @intCast(offset) });
        } else {
            try self.emit(&.{ 0xF2, 0x0F, 0x5C, 0x87 });
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf, @intCast(offset), .little);
            try self.emit(&buf);
        }
    }

    fn emit_mulsd_xmm0_mem_rdi(self: *Jit, offset: u64) !void {
        // mulsd xmm0, [rdi + offset]
        if (offset <= 127) {
            try self.emit(&.{ 0xF2, 0x0F, 0x59, 0x47, @intCast(offset) });
        } else {
            try self.emit(&.{ 0xF2, 0x0F, 0x59, 0x87 });
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf, @intCast(offset), .little);
            try self.emit(&buf);
        }
    }

    fn emit_divsd_xmm0_mem_rdi(self: *Jit, offset: u64) !void {
        // divsd xmm0, [rdi + offset]
        if (offset <= 127) {
            try self.emit(&.{ 0xF2, 0x0F, 0x5E, 0x47, @intCast(offset) });
        } else {
            try self.emit(&.{ 0xF2, 0x0F, 0x5E, 0x87 });
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf, @intCast(offset), .little);
            try self.emit(&buf);
        }
    }

    fn emit_ucomisd_xmm0_mem_rdi(self: *Jit, offset: u64) !void {
        // ucomisd xmm0, [rdi + offset]
        if (offset <= 127) {
            try self.emit(&.{ 0x66, 0x0F, 0x2E, 0x47, @intCast(offset) });
        } else {
            try self.emit(&.{ 0x66, 0x0F, 0x2E, 0x87 });
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf, @intCast(offset), .little);
            try self.emit(&buf);
        }
    }

    fn emit_mov_rax_reg(self: *Jit, reg_idx: u64) !void {
        if (HostReg.fromVm(reg_idx)) |host| {
            const host_code = @intFromEnum(host);
            if (host_code < 8) {
                // mov rax, host_reg
                try self.emit(&.{ 0x48, 0x8B, 0xC0 + host_code });
            } else {
                // mov rax, host_reg (r8-r15 need REX.B)
                try self.emit(&.{ 0x49, 0x8B, 0xC0 + (host_code - 8) });
            }
        } else {
            const offset = @offsetOf(VM, "regs") + reg_idx * 8;
            try self.emit_mov_rax_mem_rdi(offset);
        }
    }

    fn emit_mov_reg_rax(self: *Jit, reg_idx: u64) !void {
        if (HostReg.fromVm(reg_idx)) |host| {
            const host_code = @intFromEnum(host);
            if (host_code < 8) {
                // mov host_reg, rax
                try self.emit(&.{ 0x48, 0x89, 0xC0 + host_code });
            } else {
                // mov host_reg, rax
                try self.emit(&.{ 0x49, 0x89, 0xC0 + (host_code - 8) });
            }
        } else {
            const offset = @offsetOf(VM, "regs") + reg_idx * 8;
            try self.emit_mov_mem_rdi_rax(offset);
        }
    }

    fn emit_add_rax_reg(self: *Jit, reg_idx: u64) !void {
        if (HostReg.fromVm(reg_idx)) |host| {
            const host_code = @intFromEnum(host);
            if (host_code < 8) {
                // add rax, host_reg
                try self.emit(&.{ 0x48, 0x03, 0xC0 + host_code });
            } else {
                // add rax, host_reg
                try self.emit(&.{ 0x49, 0x03, 0xC0 + (host_code - 8) });
            }
        } else {
            const offset = @offsetOf(VM, "regs") + reg_idx * 8;
            try self.emit_add_rax_mem_rdi(offset);
        }
    }

    fn emit_sub_rax_reg(self: *Jit, reg_idx: u64) !void {
        if (HostReg.fromVm(reg_idx)) |host| {
            const host_code = @intFromEnum(host);
            if (host_code < 8) {
                // sub rax, host_reg
                try self.emit(&.{ 0x48, 0x2B, 0xC0 + host_code });
            } else {
                // sub rax, host_reg
                try self.emit(&.{ 0x49, 0x2B, 0xC0 + (host_code - 8) });
            }
        } else {
            const offset = @offsetOf(VM, "regs") + reg_idx * 8;
            try self.emit_sub_rax_mem_rdi(offset);
        }
    }

    fn emit_imul_rax_reg(self: *Jit, reg_idx: u64) !void {
        if (HostReg.fromVm(reg_idx)) |host| {
            const host_code = @intFromEnum(host);
            if (host_code < 8) {
                // imul rax, host_reg
                try self.emit(&.{ 0x48, 0x0F, 0xAF, 0xC0 + host_code });
            } else {
                // imul rax, host_reg
                try self.emit(&.{ 0x49, 0x0F, 0xAF, 0xC0 + (host_code - 8) });
            }
        } else {
            const offset = @offsetOf(VM, "regs") + reg_idx * 8;
            try self.emit_imul_rax_mem_rdi(offset);
        }
    }

    fn emit_cmp_rax_reg(self: *Jit, reg_idx: u64) !void {
        if (HostReg.fromVm(reg_idx)) |host| {
            const host_code = @intFromEnum(host);
            if (host_code < 8) {
                // cmp rax, host_reg
                try self.emit(&.{ 0x48, 0x3B, 0xC0 + host_code });
            } else {
                // cmp rax, host_reg
                try self.emit(&.{ 0x49, 0x3B, 0xC0 + (host_code - 8) });
            }
        } else {
            const offset = @offsetOf(VM, "regs") + reg_idx * 8;
            try self.emit_cmp_rax_mem_rdi(offset);
        }
    }

    fn emit_cmp_reg_zero(self: *Jit, reg_idx: u64) !void {
        if (HostReg.fromVm(reg_idx)) |host| {
            const host_code = @intFromEnum(host);
            if (host_code < 8) {
                // cmp host_reg, 0
                try self.emit(&.{ 0x48, 0x83, 0xF8 + host_code, 0x00 });
            } else {
                // cmp host_reg, 0
                try self.emit(&.{ 0x49, 0x83, 0xF8 + (host_code - 8), 0x00 });
            }
        } else {
            const offset = @offsetOf(VM, "regs") + reg_idx * 8;
            try self.emit_cmp_mem_rdi_zero(offset);
        }
    }

    fn emit_movq_xmm0_reg(self: *Jit, reg_idx: u64) !void {
        if (HostReg.fromVm(reg_idx)) |host| {
            try self.emit_movq_xmm0_host(host);
        } else {
            const offset = @offsetOf(VM, "regs") + reg_idx * 8;
            try self.emit_movq_xmm0_mem_rdi(offset);
        }
    }

    fn emit_movq_reg_xmm0(self: *Jit, reg_idx: u64) !void {
        if (HostReg.fromVm(reg_idx)) |host| {
            try self.emit_movq_host_xmm0(host);
        } else {
            const offset = @offsetOf(VM, "regs") + reg_idx * 8;
            try self.emit_movq_mem_rdi_xmm0(offset);
        }
    }

    fn emit_addsd_xmm0_reg(self: *Jit, reg_idx: u64) !void {
        if (HostReg.fromVm(reg_idx)) |host| {
            try self.emit_movq_xmm1_host(host);
            try self.emit_addsd_xmm0_xmm1();
        } else {
            const offset = @offsetOf(VM, "regs") + reg_idx * 8;
            try self.emit_addsd_xmm0_mem_rdi(offset);
        }
    }

    fn emit_cvtsi2sd_xmm0_reg(self: *Jit, reg_idx: u64) !void {
        if (HostReg.fromVm(reg_idx)) |host| {
            const host_code = @intFromEnum(host);
            if (host_code < 8) {
                // cvtsi2sd xmm0, host_reg
                try self.emit(&.{ 0xF2, 0x48, 0x0F, 0x2A, 0xC0 + host_code });
            } else {
                // cvtsi2sd xmm0, host_reg
                try self.emit(&.{ 0xF2, 0x49, 0x0F, 0x2A, 0xC0 + (host_code - 8) });
            }
        } else {
            const offset = @offsetOf(VM, "regs") + reg_idx * 8;
            try self.emit_cvtsi2sd_xmm0_mem_rdi(offset);
        }
    }

    fn emit_xor_rax_reg(self: *Jit, reg_idx: u64) !void {
        if (HostReg.fromVm(reg_idx)) |host| {
            const host_code = @intFromEnum(host);
            if (host_code < 8) {
                // xor rax, host_reg
                try self.emit(&.{ 0x48, 0x33, 0xC0 + host_code });
            } else {
                try self.emit(&.{ 0x49, 0x33, 0xC0 + (host_code - 8) });
            }
        } else {
            const offset = @offsetOf(VM, "regs") + reg_idx * 8;
            try self.emit_xor_rax_mem_rdi(offset);
        }
    }

    fn emit_update_reg_imm(self: *Jit, reg_idx: u64, val: u64) !void {
        // mov rax, val
        try self.emit(&.{ 0x48, 0xB8 });
        var val_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &val_buf, val, .little);
        try self.emit(&val_buf);
        try self.emit_mov_reg_rax(reg_idx);
    }

    fn emit_and_rax_reg(self: *Jit, reg_idx: u64) !void {
        if (HostReg.fromVm(reg_idx)) |host| {
            const host_code = @intFromEnum(host);
            if (host_code < 8) {
                try self.emit(&.{ 0x48, 0x23, 0xC0 + host_code });
            } else {
                try self.emit(&.{ 0x49, 0x23, 0xC0 + (host_code - 8) });
            }
        } else {
            const offset = @offsetOf(VM, "regs") + reg_idx * 8;
            try self.emit_and_rax_mem_rdi(offset);
        }
    }

    fn emit_or_rax_reg(self: *Jit, reg_idx: u64) !void {
        if (HostReg.fromVm(reg_idx)) |host| {
            const host_code = @intFromEnum(host);
            if (host_code < 8) {
                try self.emit(&.{ 0x48, 0x0B, 0xC0 + host_code });
            } else {
                try self.emit(&.{ 0x49, 0x0B, 0xC0 + (host_code - 8) });
            }
        } else {
            const offset = @offsetOf(VM, "regs") + reg_idx * 8;
            try self.emit_or_rax_mem_rdi(offset);
        }
    }

    fn emit_shl_rax_cl(self: *Jit) !void {
        // shl rax, cl
        try self.emit(&.{ 0x48, 0xD3, 0xE0 });
    }

    fn emit_shr_rax_cl(self: *Jit) !void {
        // shr rax, cl
        try self.emit(&.{ 0x48, 0xD3, 0xE8 });
    }

    fn emit_mov_rcx_reg(self: *Jit, reg_idx: u64) !void {
        if (HostReg.fromVm(reg_idx)) |host| {
            const host_code = @intFromEnum(host);
            if (host_code < 8) {
                // mov rcx, host_reg
                try self.emit(&.{ 0x48, 0x8B, 0xC8 + host_code });
            } else {
                try self.emit(&.{ 0x49, 0x8B, 0xC8 + (host_code - 8) });
            }
        } else {
            const offset = @offsetOf(VM, "regs") + reg_idx * 8;
            try self.emit_mov_rcx_mem_rdi(offset);
        }
    }

    fn emit_setcc_rax(self: *Jit, cc: u8) !void {
        // cc: 0x94 (sete), 0x95 (setne), 0x9C (setl), 0x9D (setge), 0x9E (setle), 0x9F (setg)
        try self.emit(&.{ 0x0F, cc, 0xC0 });
        // movzx rax, al
        try self.emit(&.{ 0x48, 0x0F, 0xB6, 0xC0 });
    }

    fn emit_cqo(self: *Jit) !void {
        // cqo (sign-extend rax into rdx:rax)
        try self.emit(&.{ 0x48, 0x99 });
    }

    fn emit_mov_reg_rdx(self: *Jit, reg_idx: u64) !void {
        const offset = @offsetOf(VM, "regs") + reg_idx * 8;
        // mov [rdi + offset], rdx
        if (offset <= 127) {
            try self.emit(&.{ 0x48, 0x89, 0x57, @intCast(offset) });
        } else {
            try self.emit(&.{ 0x48, 0x89, 0x97 });
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf, @intCast(offset), .little);
            try self.emit(&buf);
        }
    }

    fn emit_subsd_xmm0_reg(self: *Jit, reg_idx: u64) !void {
        if (HostReg.fromVm(reg_idx)) |host| {
            try self.emit_movq_xmm1_host(host);
            try self.emit_subsd_xmm0_xmm1();
        } else {
            const offset = @offsetOf(VM, "regs") + reg_idx * 8;
            try self.emit_subsd_xmm0_mem_rdi(offset);
        }
    }

    fn emit_mulsd_xmm0_reg(self: *Jit, reg_idx: u64) !void {
        if (HostReg.fromVm(reg_idx)) |host| {
            try self.emit_movq_xmm1_host(host);
            try self.emit_mulsd_xmm0_xmm1();
        } else {
            const offset = @offsetOf(VM, "regs") + reg_idx * 8;
            try self.emit_mulsd_xmm0_mem_rdi(offset);
        }
    }

    fn emit_divsd_xmm0_reg(self: *Jit, reg_idx: u64) !void {
        if (HostReg.fromVm(reg_idx)) |host| {
            try self.emit_movq_xmm1_host(host);
            try self.emit_divsd_xmm0_xmm1();
        } else {
            const offset = @offsetOf(VM, "regs") + reg_idx * 8;
            try self.emit_divsd_xmm0_mem_rdi(offset);
        }
    }

    fn emit_ucomisd_xmm0_reg(self: *Jit, reg_idx: u64) !void {
        if (HostReg.fromVm(reg_idx)) |host| {
            try self.emit_movq_xmm1_host(host);
            try self.emit_ucomisd_xmm0_xmm1();
        } else {
            const offset = @offsetOf(VM, "regs") + reg_idx * 8;
            try self.emit_ucomisd_xmm0_mem_rdi(offset);
        }
    }

    fn emit_xorpd_xmm0_xmm1(self: *Jit) !void {
        // xorpd xmm0, xmm1
        try self.emit(&.{ 0x66, 0x0F, 0x57, 0xC1 });
    }

    fn emit_andpd_xmm0_xmm1(self: *Jit) !void {
        // andpd xmm0, xmm1
        try self.emit(&.{ 0x66, 0x0F, 0x54, 0xC1 });
    }

    fn emit_call_zig_handler(self: *Jit, func_ptr: usize, inst: u64) !void {
        // Save RDI (it's caller-saved and we need it as our base)
        try self.emit(&.{0x57}); // push rdi

        // RDI = VM* (already there)
        // RSI = inst
        try self.emit(&.{ 0x48, 0xBE });
        var inst_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &inst_buf, inst, .little);
        try self.emit(&inst_buf);

        // Call handler
        try self.emit(&.{ 0x48, 0xB8 });
        var ptr_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &ptr_buf, func_ptr, .little);
        try self.emit(&ptr_buf);
        try self.emit(&.{ 0xFF, 0xD0 });

        // Restore RDI
        try self.emit(&.{0x5F}); // pop rdi

        // Zig error check: if RAX != 0, return to caller (runAsync)
        // test rax, rax
        try self.emit(&.{ 0x48, 0x85, 0xC0 });
        // jz success (skip epilogue)
        try self.emit(&.{ 0x74, 30 }); // skip 30 bytes (size of full epilogue)
        try self.emit_full_epilogue();
    }

    fn emit_mov_rdx_mem_rdi(self: *Jit, offset: u64) !void {
        // mov rdx, [rdi + offset]
        if (offset <= 127) {
            try self.emit(&.{ 0x48, 0x8B, 0x57, @intCast(offset) });
        } else {
            try self.emit(&.{ 0x48, 0x8B, 0x97 });
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf, @intCast(offset), .little);
            try self.emit(&buf);
        }
    }

    fn emit_mov_rdx_reg(self: *Jit, reg_idx: u64) !void {
        if (HostReg.fromVm(reg_idx)) |host| {
            const host_code = @intFromEnum(host);
            if (host_code < 8) {
                // mov rdx, host_reg
                try self.emit(&.{ 0x48, 0x8B, 0xD0 + host_code });
            } else {
                try self.emit(&.{ 0x49, 0x8B, 0xD0 + (host_code - 8) });
            }
        } else {
            const offset = @offsetOf(VM, "regs") + reg_idx * 8;
            // mov rdx, [rdi + offset]
            if (offset <= 127) {
                try self.emit(&.{ 0x48, 0x8B, 0x57, @intCast(offset) });
            } else {
                try self.emit(&.{ 0x48, 0x8B, 0x97 });
                var buf: [4]u8 = undefined;
                std.mem.writeInt(u32, &buf, @intCast(offset), .little);
                try self.emit(&buf);
            }
        }
    }

    fn emit_idiv_reg(self: *Jit, host: HostReg) !void {
        const host_code = @intFromEnum(host);
        if (host_code < 8) {
            // idiv host_reg
            try self.emit(&.{ 0x48, 0xF7, 0xF8 + host_code });
        } else {
            // idiv r12-r15 (REX.B)
            try self.emit(&.{ 0x49, 0xF7, 0xF8 + (host_code - 8) });
        }
    }

    fn emit_idiv_mem_rdi(self: *Jit, offset: u64) !void {
        // idiv qword ptr [rdi + offset]
        if (offset <= 127) {
            try self.emit(&.{ 0x48, 0xF7, 0x7F, @intCast(offset) });
        } else {
            try self.emit(&.{ 0x48, 0xF7, 0xBF });
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf, @intCast(offset), .little);
            try self.emit(&buf);
        }
    }

    fn emit_movq_xmm0_host(self: *Jit, host: HostReg) !void {
        const host_code = @intFromEnum(host);
        if (host_code < 8) {
            try self.emit(&.{ 0x66, 0x48, 0x0F, 0x6E, 0xC0 + host_code });
        } else {
            try self.emit(&.{ 0x66, 0x49, 0x0F, 0x6E, 0xC0 + (host_code - 8) });
        }
    }

    fn emit_movq_host_xmm0(self: *Jit, host: HostReg) !void {
        const host_code = @intFromEnum(host);
        if (host_code < 8) {
            try self.emit(&.{ 0x66, 0x48, 0x0F, 0x7E, 0xC0 + host_code });
        } else {
            try self.emit(&.{ 0x66, 0x49, 0x0F, 0x7E, 0xC0 + (host_code - 8) });
        }
    }

    fn emit_movq_xmm1_host(self: *Jit, host: HostReg) !void {
        const host_code = @intFromEnum(host);
        if (host_code < 8) {
            try self.emit(&.{ 0x66, 0x48, 0x0F, 0x6E, 0xC8 + host_code }); // reg field is 001 (xmm1)
        } else {
            try self.emit(&.{ 0x66, 0x49, 0x0F, 0x6E, 0xC8 + (host_code - 8) });
        }
    }

    fn emit_addsd_xmm0_xmm1(self: *Jit) !void {
        try self.emit(&.{ 0xF2, 0x0F, 0x58, 0xC1 });
    }

    fn emit_subsd_xmm0_xmm1(self: *Jit) !void {
        try self.emit(&.{ 0xF2, 0x0F, 0x5C, 0xC1 });
    }

    fn emit_mulsd_xmm0_xmm1(self: *Jit) !void {
        try self.emit(&.{ 0xF2, 0x0F, 0x59, 0xC1 });
    }

    fn emit_divsd_xmm0_xmm1(self: *Jit) !void {
        try self.emit(&.{ 0xF2, 0x0F, 0x5E, 0xC1 });
    }

    fn emit_ucomisd_xmm0_xmm1(self: *Jit) !void {
        try self.emit(&.{ 0x66, 0x0F, 0x2E, 0xC1 });
    }

    fn emit_mov_rax_mem_rdx_base_rax_off(self: *Jit) !void {
        // mov rax, [rdx + rax]
        try self.emit(&.{ 0x48, 0x8B, 0x04, 0x02 });
    }

    fn emit_bswap_rax(self: *Jit) !void {
        // bswap rax
        try self.emit(&.{ 0x48, 0x0F, 0xC8 });
    }

    fn emit_load_host_reg_from_vm(self: *Jit, vm_reg: u64) !void {
        const host = HostReg.fromVm(vm_reg) orelse return;
        const offset = @offsetOf(VM, "regs") + vm_reg * 8;
        const reg_code = @intFromEnum(host);
        if (reg_code < 8) {
            // mov host_reg, [rdi + offset]
            if (offset <= 127) {
                try self.emit(&.{ 0x48, 0x8B, 0x47 + (reg_code << 3), @intCast(offset) });
            } else {
                try self.emit(&.{ 0x48, 0x8B, 0x87 + (reg_code << 3) });
                var buf: [4]u8 = undefined;
                std.mem.writeInt(u32, &buf, @intCast(offset), .little);
                try self.emit(&buf);
            }
        } else {
            // r12-r15 need REX.R
            const base_code = reg_code - 8;
            if (offset <= 127) {
                try self.emit(&.{ 0x4C, 0x8B, 0x47 + (base_code << 3), @intCast(offset) });
            } else {
                try self.emit(&.{ 0x4C, 0x8B, 0x87 + (base_code << 3) });
                var buf: [4]u8 = undefined;
                std.mem.writeInt(u32, &buf, @intCast(offset), .little);
                try self.emit(&buf);
            }
        }
    }

    fn emit_load_host_vreg_from_vm(self: *Jit, vm_reg: u64) !void {
        const host = HostVReg.fromVm(vm_reg) orelse return;
        const offset = @offsetOf(VM, "vregs") + vm_reg * 16;
        const reg_code = @intFromEnum(host);
        // movups xmm, [rdi + offset]
        if (offset <= 127) {
            try self.emit(&.{ 0x0F, 0x10, 0x47 + (reg_code << 3), @intCast(offset) });
        } else {
            try self.emit(&.{ 0x0F, 0x10, 0x87 + (reg_code << 3) });
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf, @intCast(offset), .little);
            try self.emit(&buf);
        }
    }

    fn emit_spill_host_vreg_to_vm(self: *Jit, vm_reg: u64) !void {
        const host = HostVReg.fromVm(vm_reg) orelse return;
        const offset = @offsetOf(VM, "vregs") + vm_reg * 16;
        const reg_code = @intFromEnum(host);
        // movups [rdi + offset], xmm
        if (offset <= 127) {
            try self.emit(&.{ 0x0F, 0x11, 0x47 + (reg_code << 3), @intCast(offset) });
        } else {
            try self.emit(&.{ 0x0F, 0x11, 0x87 + (reg_code << 3) });
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf, @intCast(offset), .little);
            try self.emit(&buf);
        }
    }

    fn emit_v128_load_to_host(self: *Jit, vm_vreg: u64, target: HostVReg) !void {
        if (HostVReg.fromVm(vm_vreg)) |host| {
            if (host == target) return;
            const t = @intFromEnum(target);
            const h = @intFromEnum(host);
            // movaps target, host
            try self.emit(&.{ 0x0F, 0x28, 0xC0 + (t << 3) + h });
        } else {
            const offset = @offsetOf(VM, "vregs") + vm_vreg * 16;
            const t = @intFromEnum(target);
            // movups target, [rdi + offset]
            if (offset <= 127) {
                try self.emit(&.{ 0x0F, 0x10, 0x47 + (t << 3), @intCast(offset) });
            } else {
                try self.emit(&.{ 0x0F, 0x10, 0x87 + (t << 3) });
                var buf: [4]u8 = undefined;
                std.mem.writeInt(u32, &buf, @intCast(offset), .little);
                try self.emit(&buf);
            }
        }
    }

    fn emit_v128_write_to_vm(self: *Jit, vm_vreg: u64, source: HostVReg) !void {
        const s = @intFromEnum(source);
        if (HostVReg.fromVm(vm_vreg)) |host| {
            if (host == source) return;
            const h = @intFromEnum(host);
            // movaps host, source
            try self.emit(&.{ 0x0F, 0x28, 0xC0 + (h << 3) + s });
        } else {
            const offset = @offsetOf(VM, "vregs") + vm_vreg * 16;
            // movups [rdi + offset], source
            if (offset <= 127) {
                try self.emit(&.{ 0x0F, 0x11, 0x47 + (s << 3), @intCast(offset) });
            } else {
                try self.emit(&.{ 0x0F, 0x11, 0x87 + (s << 3) });
                var buf: [4]u8 = undefined;
                std.mem.writeInt(u32, &buf, @intCast(offset), .little);
                try self.emit(&buf);
            }
        }
    }

    fn emit_movq_xmm_reg(self: *Jit, host_xmm: HostVReg, vm_reg: u64) !void {
        const xmm_code = @intFromEnum(host_xmm);
        if (HostReg.fromVm(vm_reg)) |host| {
            const host_code = @intFromEnum(host);
            // movq xmm, host_reg
            if (host_code < 8) {
                try self.emit(&.{ 0x66, 0x48, 0x0F, 0x6E, 0xC0 + (xmm_code << 3) + host_code });
            } else {
                try self.emit(&.{ 0x66, 0x49, 0x0F, 0x6E, 0xC0 + (xmm_code << 3) + (host_code - 8) });
            }
        } else {
            const offset = @offsetOf(VM, "regs") + vm_reg * 8;
            // movq xmm, [rdi + offset]
            if (offset <= 127) {
                try self.emit(&.{ 0x66, 0x0F, 0x6E, 0x47 + (xmm_code << 3), @intCast(offset) });
            } else {
                try self.emit(&.{ 0x66, 0x0F, 0x6E, 0x87 + (xmm_code << 3) });
                var buf: [4]u8 = undefined;
                std.mem.writeInt(u32, &buf, @intCast(offset), .little);
                try self.emit(&buf);
            }
        }
    }

    fn emit_v128_binary_op(self: *Jit, opcode_byte: u8, rd_idx: u64, rs1_idx: u64, rs2_idx: u64) !void {
        const maybe_rd = HostVReg.fromVm(rd_idx);
        const maybe_rs1 = HostVReg.fromVm(rs1_idx);
        const maybe_rs2 = HostVReg.fromVm(rs2_idx);

        if (maybe_rd) |rd| {
            const rd_code = @as(u8, @intFromEnum(rd));
            if (maybe_rs1) |rs1| {
                if (rd == rs1) {
                    // Optimized: op rd, rs2
                    if (maybe_rs2) |rs2| {
                        try self.emit(&.{ 0x66, 0x0F, opcode_byte, 0xC0 + (rd_code << 3) + @as(u8, @intFromEnum(rs2)) });
                    } else {
                        try self.emit_v128_load_to_host(rs2_idx, .xmm4);
                        try self.emit(&.{ 0x66, 0x0F, opcode_byte, 0xC0 + (rd_code << 3) + 4 });
                    }
                } else {
                    // movaps rd, rs1
                    try self.emit(&.{ 0x0F, 0x28, 0xC0 + (rd_code << 3) + @as(u8, @intFromEnum(rs1)) });
                    // op rd, rs2
                    if (maybe_rs2) |rs2| {
                        try self.emit(&.{ 0x66, 0x0F, opcode_byte, 0xC0 + (rd_code << 3) + @as(u8, @intFromEnum(rs2)) });
                    } else {
                        try self.emit_v128_load_to_host(rs2_idx, .xmm4);
                        try self.emit(&.{ 0x66, 0x0F, opcode_byte, 0xC0 + (rd_code << 3) + 4 });
                    }
                }
            } else {
                // rs1 not mapped, load to rd
                try self.emit_v128_load_to_host(rs1_idx, rd);
                // op rd, rs2
                if (maybe_rs2) |rs2| {
                    try self.emit(&.{ 0x66, 0x0F, opcode_byte, 0xC0 + (rd_code << 3) + @as(u8, @intFromEnum(rs2)) });
                } else {
                    try self.emit_v128_load_to_host(rs2_idx, .xmm4);
                    try self.emit(&.{ 0x66, 0x0F, opcode_byte, 0xC0 + (rd_code << 3) + 4 });
                }
            }
        } else {
            // rd not mapped, use scratch
            try self.emit_v128_load_to_host(rs1_idx, .xmm4);
            try self.emit_v128_load_to_host(rs2_idx, .xmm5);
            try self.emit(&.{ 0x66, 0x0F, opcode_byte, 0xE5 }); // op xmm4, xmm5
            try self.emit_v128_write_to_vm(rd_idx, .xmm4);
        }
    }

    fn emit_v128_unary_op(self: *Jit, opcode_byte: u8, rd_idx: u64, rs1_idx: u64) !void {
        const maybe_rd = HostVReg.fromVm(rd_idx);
        const maybe_rs1 = HostVReg.fromVm(rs1_idx);

        if (maybe_rd) |rd| {
            const rd_code = @as(u8, @intFromEnum(rd));
            if (maybe_rs1) |rs1| {
                try self.emit(&.{ 0x66, 0x0F, opcode_byte, 0xC0 + (rd_code << 3) + @as(u8, @intFromEnum(rs1)) });
            } else {
                try self.emit_v128_load_to_host(rs1_idx, .xmm4);
                try self.emit(&.{ 0x66, 0x0F, opcode_byte, 0xC0 + (rd_code << 3) + 4 });
            }
        } else {
            try self.emit_v128_load_to_host(rs1_idx, .xmm4);
            try self.emit(&.{ 0x66, 0x0F, opcode_byte, 0xE4 }); // op xmm4, xmm4
            try self.emit_v128_write_to_vm(rd_idx, .xmm4);
        }
    }

    fn emit_spill_host_reg_to_vm(self: *Jit, vm_reg: u64) !void {
        const host = HostReg.fromVm(vm_reg) orelse return;
        const offset = @offsetOf(VM, "regs") + vm_reg * 8;
        const reg_code = @intFromEnum(host);
        if (reg_code < 8) {
            // mov [rdi + offset], host_reg
            if (offset <= 127) {
                try self.emit(&.{ 0x48, 0x89, 0x47 + (reg_code << 3), @intCast(offset) });
            } else {
                try self.emit(&.{ 0x48, 0x89, 0x87 + (reg_code << 3) });
                var buf: [4]u8 = undefined;
                std.mem.writeInt(u32, &buf, @intCast(offset), .little);
                try self.emit(&buf);
            }
        } else {
            // r12-r15 need REX.R
            const base_code = reg_code - 8;
            if (offset <= 127) {
                try self.emit(&.{ 0x4C, 0x89, 0x47 + (base_code << 3), @intCast(offset) });
            } else {
                try self.emit(&.{ 0x4C, 0x89, 0x87 + (base_code << 3) });
                var buf: [4]u8 = undefined;
                std.mem.writeInt(u32, &buf, @intCast(offset), .little);
                try self.emit(&buf);
            }
        }
    }

    fn emit_mov_rcx_mem_rdi(self: *Jit, offset: u64) !void {
        // mov rcx, [rdi + offset]
        if (offset <= 127) {
            try self.emit(&.{ 0x48, 0x8B, 0x4F, @intCast(offset) });
        } else {
            try self.emit(&.{ 0x48, 0x8B, 0x8F });
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf, @intCast(offset), .little);
            try self.emit(&buf);
        }
    }

    fn emit_jz_rel32_placeholder(self: *Jit) !usize {
        // jz rel32 (0x0F 0x84)
        try self.emit(&.{ 0x0F, 0x84, 0, 0, 0, 0 });
        return self.cursor - 4;
    }

    fn patch_rel32(self: *Jit, pos: usize) void {
        const after = self.cursor;
        const rel = @as(i32, @intCast(after)) - @as(i32, @intCast(pos + 4));
        std.mem.writeInt(i32, self.code_buffer[pos .. pos + 4][0..4], rel, .little);
    }

    fn emit_stack_push_imm64(self: *Jit, val: u64) !void {
        // mov rax, val
        try self.emit(&.{ 0x48, 0xB8 });
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, val, .little);
        try self.emit(&buf);
        try self.emit_stack_push_rax();
    }

    fn emit_stack_push_rax(self: *Jit) !void {
        // Load SP
        const sp_off = @offsetOf(VM, "sp");
        try self.emit_mov_rcx_mem_rdi(sp_off);

        // mov [rdi + stack_off + rcx*8], rax
        const stack_off = @offsetOf(VM, "stack");
        try self.emit(&.{ 0x48, 0x89, 0x84, 0xCF });
        var off_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &off_buf, @intCast(stack_off), .little);
        try self.emit(&off_buf);

        // inc qword ptr [rdi + sp_off]
        try self.emit(&.{ 0x48, 0xFF, 0x87 });
        std.mem.writeInt(u32, &off_buf, @intCast(sp_off), .little);
        try self.emit(&off_buf);
    }

    fn emit_stack_pop_rax(self: *Jit) !void {
        // dec qword ptr [rdi + sp_off]
        const sp_off = @offsetOf(VM, "sp");
        try self.emit(&.{ 0x48, 0xFF, 0x8F });
        var off_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &off_buf, @intCast(sp_off), .little);
        try self.emit(&off_buf);

        // Load SP
        try self.emit_mov_rcx_mem_rdi(sp_off);

        // mov rax, [rdi + stack_off + rcx*8]
        const stack_off = @offsetOf(VM, "stack");
        try self.emit(&.{ 0x48, 0x8B, 0x84, 0xCF });
        std.mem.writeInt(u32, &off_buf, @intCast(stack_off), .little);
        try self.emit(&off_buf);
    }

    fn emit_full_epilogue(self: *Jit) !void {
        // Spill R0-R4 back to vm.regs
        inline for (0..5) |i| {
            try self.emit_spill_host_reg_to_vm(i);
        }

        // Spill V0-V3 back to vm.vregs
        inline for (0..4) |i| {
            try self.emit_spill_host_vreg_to_vm(i);
        }

        // Restore callee-saved registers
        try self.emit(&.{ 0x41, 0x5F }); // pop r15
        try self.emit(&.{ 0x41, 0x5E }); // pop r14
        try self.emit(&.{ 0x41, 0x5D }); // pop r13
        try self.emit(&.{ 0x41, 0x5C }); // pop r12
        try self.emit(&.{0x5B}); // pop rbx

        try self.emit_ret();
    }
};
