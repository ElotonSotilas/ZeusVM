const std = @import("std");
const ZeusVM = @import("../root.zig");
const Opcode = ZeusVM.opcode.Opcode;

pub const Token = struct {
    tag: Tag,
    loc: Loc,

    pub const Tag = enum {
        mnemonic,
        register,
        label_def,
        label_ref,
        immediate,
        directive,
        comma,
        newline,
        eof,
    };

    pub const Loc = struct {
        line: usize,
        col: usize,
        text: []const u8,
    };
};

pub const Assembler = struct {
    allocator: std.mem.Allocator,
    source: []const u8,
    tokens: std.ArrayList(Token),
    labels: std.StringHashMap(u64),
    output: std.ArrayList(u8),

    pub fn init(allocator: std.mem.Allocator, source: []const u8) Assembler {
        return .{
            .allocator = allocator,
            .source = source,
            .tokens = .{},
            .labels = std.StringHashMap(u64).init(allocator),
            .output = .{},
        };
    }

    pub fn deinit(self: *Assembler) void {
        self.tokens.deinit(self.allocator);
        self.labels.deinit();
        self.output.deinit(self.allocator);
    }

    pub fn tokenize(self: *Assembler) !void {
        var line: usize = 1;
        var col: usize = 1;
        var i: usize = 0;

        while (i < self.source.len) {
            const c = self.source[i];

            if (std.ascii.isWhitespace(c)) {
                if (c == '\n') {
                    try self.tokens.append(self.allocator, .{ .tag = .newline, .loc = .{ .line = line, .col = col, .text = "\n" } });
                    line += 1;
                    col = 1;
                } else {
                    col += 1;
                }
                i += 1;
                continue;
            }

            if (c == ';') { // Comments
                while (i < self.source.len and self.source[i] != '\n') : (i += 1) {}
                continue;
            }

            if (c == ',') {
                try self.tokens.append(self.allocator, .{ .tag = .comma, .loc = .{ .line = line, .col = col, .text = "," } });
                i += 1;
                col += 1;
                continue;
            }

            if (c == '.') { // Directive
                const start = i;
                i += 1;
                while (i < self.source.len and (std.ascii.isAlphabetic(self.source[i]) or std.ascii.isDigit(self.source[i]) or self.source[i] == '_')) : (i += 1) {}
                try self.tokens.append(self.allocator, .{ .tag = .directive, .loc = .{ .line = line, .col = col, .text = self.source[start..i] } });
                col += i - start;
                continue;
            }

            if (std.ascii.isDigit(c) or (c == '-' and i + 1 < self.source.len and std.ascii.isDigit(self.source[i + 1]))) { // Immediate
                const start = i;
                i += 1;
                while (i < self.source.len and (std.ascii.isDigit(self.source[i]) or self.source[i] == '.' or self.source[i] == 'x' or (self.source[i] >= 'a' and self.source[i] <= 'f') or (self.source[i] >= 'A' and self.source[i] <= 'F'))) : (i += 1) {}
                try self.tokens.append(self.allocator, .{ .tag = .immediate, .loc = .{ .line = line, .col = col, .text = self.source[start..i] } });
                col += i - start;
                continue;
            }

            if (c == '@') { // Label Reference
                const start = i;
                i += 1;
                while (i < self.source.len and (std.ascii.isAlphabetic(self.source[i]) or std.ascii.isDigit(self.source[i]) or self.source[i] == '_')) : (i += 1) {}
                try self.tokens.append(self.allocator, .{ .tag = .label_ref, .loc = .{ .line = line, .col = col, .text = self.source[start..i] } });
                col += i - start;
                continue;
            }

            if (std.ascii.isAlphabetic(c) or c == '_') {
                const start = i;
                i += 1;
                while (i < self.source.len and (std.ascii.isAlphabetic(self.source[i]) or std.ascii.isDigit(self.source[i]) or self.source[i] == '_')) : (i += 1) {}

                const text = self.source[start..i];
                if (i < self.source.len and self.source[i] == ':') { // Label Definition
                    try self.tokens.append(self.allocator, .{ .tag = .label_def, .loc = .{ .line = line, .col = col, .text = text } });
                    i += 1;
                    col += i - start;
                } else if (text.len >= 2 and (text[0] == 'R' or text[0] == 'r' or text[0] == 'V' or text[0] == 'v') and std.ascii.isDigit(text[1])) { // Register?
                    var all_digits = true;
                    for (text[2..]) |reg_c| {
                        if (!std.ascii.isDigit(reg_c)) {
                            all_digits = false;
                            break;
                        }
                    }
                    if (all_digits) {
                        try self.tokens.append(self.allocator, .{ .tag = .register, .loc = .{ .line = line, .col = col, .text = text } });
                    } else {
                        try self.tokens.append(self.allocator, .{ .tag = .mnemonic, .loc = .{ .line = line, .col = col, .text = text } });
                    }
                    col += i - start;
                } else { // Mnemonic
                    try self.tokens.append(self.allocator, .{ .tag = .mnemonic, .loc = .{ .line = line, .col = col, .text = text } });
                    col += i - start;
                }
                continue;
            }

            if (c == '"') { // String literal (in directives)
                const start = i;
                i += 1;
                while (i < self.source.len and self.source[i] != '"') : (i += 1) {
                    if (self.source[i] == '\\') i += 1;
                }
                if (i < self.source.len) i += 1;
                try self.tokens.append(self.allocator, .{ .tag = .immediate, .loc = .{ .line = line, .col = col, .text = self.source[start..i] } });
                col += i - start;
                continue;
            }

            // Unknown character
            std.debug.print("Assembler Error: Unknown character '{c}' at {}:{}\n", .{ c, line, col });
            return error.InvalidCharacter;
        }

        try self.tokens.append(self.allocator, .{ .tag = .eof, .loc = .{ .line = line, .col = col, .text = "" } });
    }

    fn calculateStringLen(self: *Assembler, text: []const u8) usize {
        _ = self;
        var len: usize = 0;
        var i: usize = 0;
        while (i < text.len) {
            if (text[i] == '\\' and i + 1 < text.len) {
                i += 2;
            } else {
                i += 1;
            }
            len += 1;
        }
        return len;
    }

    pub fn assemble(self: *Assembler) ![]u8 {
        try self.tokenize();

        // Pass 1: Labels
        try self.pass1();

        // Pass 2: Encoding
        try self.pass2();

        return self.output.toOwnedSlice(self.allocator);
    }

    fn pass1(self: *Assembler) !void {
        var cursor: u64 = 0;
        var i: usize = 0;
        while (i < self.tokens.items.len) {
            const tok = self.tokens.items[i];
            switch (tok.tag) {
                .label_def => {
                    try self.labels.put(tok.loc.text, cursor);
                    i += 1;
                },
                .newline => i += 1,
                .mnemonic => {
                    cursor += 8;
                    // Skip to next newline or EOF
                    while (i < self.tokens.items.len and self.tokens.items[i].tag != .newline and self.tokens.items[i].tag != .eof) : (i += 1) {}
                },
                .directive => {
                    if (std.mem.eql(u8, tok.loc.text, ".u64") or std.mem.eql(u8, tok.loc.text, ".f64")) {
                        cursor += 8;
                    } else if (std.mem.eql(u8, tok.loc.text, ".string")) {
                        // Find string length
                        i += 1;
                        if (i < self.tokens.items.len and self.tokens.items[i].tag == .immediate) {
                            var str = self.tokens.items[i].loc.text;
                            str = str[1 .. str.len - 1]; // remove quotes
                            cursor += self.calculateStringLen(str) + 1; // plus null
                        }
                    } else if (std.mem.eql(u8, tok.loc.text, ".org")) {
                        i += 1;
                        if (i < self.tokens.items.len and self.tokens.items[i].tag == .immediate) {
                            cursor = try std.fmt.parseInt(u64, self.tokens.items[i].loc.text, 0);
                        }
                    }
                    while (i < self.tokens.items.len and self.tokens.items[i].tag != .newline and self.tokens.items[i].tag != .eof) : (i += 1) {}
                },
                .eof => break,
                else => i += 1,
            }
        }
    }

    fn pass2(self: *Assembler) !void {
        var cursor: u64 = 0;
        var i: usize = 0;
        while (i < self.tokens.items.len) {
            const tok = self.tokens.items[i];
            switch (tok.tag) {
                .mnemonic => {
                    const mnemonic = tok.loc.text;
                    const op = self.mnemonicToOpcode(mnemonic) catch |err| {
                        std.debug.print("Assembler Error: Unknown mnemonic '{s}' at {}:{}\n", .{ mnemonic, tok.loc.line, tok.loc.col });
                        return err;
                    };

                    var rd_val: u8 = 0;
                    var rs1_val: u8 = 0;
                    var rs2_val: u8 = 0;
                    var imm_val: u64 = 0;

                    const sig = self.getOpcodeSignature(op);

                    i += 1;

                    var reg_idx: usize = 0;
                    while (i < self.tokens.items.len and self.tokens.items[i].tag != .newline and self.tokens.items[i].tag != .eof) {
                        const arg_tok = self.tokens.items[i];
                        if (arg_tok.tag == .comma) {
                            i += 1;
                            continue;
                        }

                        if (arg_tok.tag == .register) {
                            const reg = try self.parseRegister(arg_tok.loc.text);
                            // Map this register based on signature
                            if (reg_idx < sig.regs.len) {
                                switch (sig.regs[reg_idx]) {
                                    .rd => rd_val = reg,
                                    .rs1 => rs1_val = reg,
                                    .rs2 => rs2_val = reg,
                                }
                            }
                            reg_idx += 1;
                        } else if (arg_tok.tag == .immediate) {
                            imm_val = try self.parseImmediate(arg_tok.loc.text);
                        } else if (arg_tok.tag == .label_ref) {
                            const label_name = arg_tok.loc.text[1..]; // skip @
                            imm_val = @intCast(self.labels.get(label_name) orelse {
                                std.debug.print("Assembler Error: Undefined label '{s}' at {}:{}\n", .{ label_name, arg_tok.loc.line, arg_tok.loc.col });
                                return error.UndefinedLabel;
                            });
                        }
                        i += 1;
                    }

                    // Encode instruction
                    var inst: u64 = 0;
                    inst |= @as(u64, @intFromEnum(op)) << 56;
                    inst |= @as(u64, rd_val) << 48;
                    inst |= @as(u64, rs1_val) << 40;
                    inst |= @as(u64, rs2_val) << 32;
                    inst |= @as(u32, @intCast(imm_val & 0xFFFFFFFF));

                    var buf: [8]u8 = undefined;
                    std.mem.writeInt(u64, &buf, inst, .big);
                    try self.output.appendSlice(self.allocator, &buf);
                    cursor += 8;
                },
                .directive => {
                    if (std.mem.eql(u8, tok.loc.text, ".u64")) {
                        i += 1;
                        const val = try self.parseImmediate(self.tokens.items[i].loc.text);
                        var buf: [8]u8 = undefined;
                        std.mem.writeInt(u64, &buf, val, .big);
                        try self.output.appendSlice(self.allocator, &buf);
                        cursor += 8;
                    } else if (std.mem.eql(u8, tok.loc.text, ".f64")) {
                        i += 1;
                        const val = try self.parseF64(self.tokens.items[i].loc.text);
                        var buf: [8]u8 = undefined;
                        std.mem.writeInt(u64, &buf, @bitCast(val), .big);
                        try self.output.appendSlice(self.allocator, &buf);
                        cursor += 8;
                    } else if (std.mem.eql(u8, tok.loc.text, ".string")) {
                        i += 1;
                        var str = self.tokens.items[i].loc.text;
                        str = str[1 .. str.len - 1]; // Remove quotes
                        const unescaped = try self.unescape(str);
                        defer self.allocator.free(unescaped);

                        try self.output.appendSlice(self.allocator, unescaped);
                        try self.output.append(self.allocator, 0);
                        cursor += unescaped.len + 1;
                    } else if (std.mem.eql(u8, tok.loc.text, ".org")) {
                        i += 1;
                        const target = try self.parseImmediate(self.tokens.items[i].loc.text);
                        const diff = target - cursor;
                        for (0..diff) |_| try self.output.append(self.allocator, 0);
                        cursor = target;
                    }
                    while (i < self.tokens.items.len and self.tokens.items[i].tag != .newline and self.tokens.items[i].tag != .eof) : (i += 1) {}
                },
                .newline => i += 1,
                .label_def => i += 1,
                .eof => break,
                else => {
                    std.debug.print("Assembler Error: Unexpected token '{s}' at {}:{}\n", .{ tok.loc.text, tok.loc.line, tok.loc.col });
                    return error.UnexpectedToken;
                },
            }
        }
    }

    fn getOpcodeSignature(self: *const Assembler, op: Opcode) OpcodeSignature {
        _ = self;
        return switch (op) {
            .NOP, .HALT, .RET, .THREAD_YIELD => .{ .regs = &.{} },
            .JMP, .BR, .CALL, .TIME_NOW, .HEAP_ALLOC => .{ .regs = &.{.rd} },
            .BR_IF => .{ .regs = &.{.rs1} },
            .CALL_REG => .{ .regs = &.{.rs1} },
            .IADD, .ISUB, .IMUL, .IDIV, .IMOD, .IAND, .IOR, .IXOR, .ISHL, .ISHR => .{ .regs = &.{ .rd, .rs1, .rs2 } },
            .FADD, .FSUB, .FMUL, .FDIV => .{ .regs = &.{ .rd, .rs1, .rs2 } },
            .FNEG, .FABS, .FSQRT => .{ .regs = &.{ .rd, .rs1 } },
            .LOAD, .STORE, .MEM_COPY, .MEM_ZERO, .PTR_ADD, .PTR_SUB => .{ .regs = &.{ .rd, .rs1, .rs2 } },
            .ICMP_EQ, .ICMP_NE, .ICMP_LT, .ICMP_GT, .ICMP_LE, .ICMP_GE => .{ .regs = &.{ .rd, .rs1, .rs2 } },
            .FCMP_EQ, .FCMP_NE, .FCMP_LT, .FCMP_GT, .FCMP_LE, .FCMP_GE => .{ .regs = &.{ .rd, .rs1, .rs2 } },
            .V128_F64x2_ADD, .V128_F64x2_SUB, .V128_F64x2_MUL, .V128_F64x2_DIV => .{ .regs = &.{ .rd, .rs1, .rs2 } },
            .V128_F64x2_SQRT, .V128_SPLAT_F64 => .{ .regs = &.{ .rd, .rs1 } },
            .V128_LOAD, .V128_STORE => .{ .regs = &.{ .rd, .rs1 } },
            .SLEEP_NS, .THREAD_SPAWN, .THREAD_JOIN => .{ .regs = &.{.rd} },
            .FS_OPEN => .{ .regs = &.{ .rd, .rs1, .rs2 } },
            .FS_READ, .FS_WRITE => .{ .regs = &.{ .rd, .rs1, .rs2 } },
            .FS_CLOSE, .LOAD_MODULE => .{ .regs = &.{.rs1} },
            .STDIN_READ => .{ .regs = &.{ .rd, .rs1 } },
            .STDOUT_WRITE, .STDERR_WRITE => .{ .regs = &.{.rs1} },
            .NET_OPEN, .NET_CLOSE, .NET_SEND, .NET_RECV, .NET_POLL, .NET_LISTEN, .NET_ACCEPT => .{ .regs = &.{ .rd, .rs1, .rs2 } },
            .ATOMIC_LOAD => .{ .regs = &.{ .rd, .rs1 } },
            .ATOMIC_STORE => .{ .regs = &.{ .rs1, .rs2 } },
            .ATOMIC_RMW => .{ .regs = &.{ .rd, .rs1, .rs2 } },
            .ATOMIC_CAS => .{ .regs = &.{ .rd, .rs1, .rs2 } },
            .FCONV_I2F, .FCONV_F2I => .{ .regs = &.{ .rd, .rs1 } },
            else => .{ .regs = &.{ .rd, .rs1, .rs2 } },
        };
    }

    const OpcodeSignature = struct {
        regs: []const RegField,

        const RegField = enum { rd, rs1, rs2 };
    };

    fn unescape(self: *Assembler, text: []const u8) ![]u8 {
        const len = self.calculateStringLen(text);
        var result = try self.allocator.alloc(u8, len);
        var i: usize = 0;
        var j: usize = 0;
        while (i < text.len) {
            if (text[i] == '\\' and i + 1 < text.len) {
                switch (text[i + 1]) {
                    'n' => {
                        result[j] = '\n';
                        i += 2;
                    },
                    'r' => {
                        result[j] = '\r';
                        i += 2;
                    },
                    't' => {
                        result[j] = '\t';
                        i += 2;
                    },
                    '\\' => {
                        result[j] = '\\';
                        i += 2;
                    },
                    '\"' => {
                        result[j] = '\"';
                        i += 2;
                    },
                    else => {
                        result[j] = text[i];
                        i += 1;
                    },
                }
            } else {
                result[j] = text[i];
                i += 1;
            }
            j += 1;
        }
        std.debug.assert(j == len);
        return result;
    }

    fn mnemonicToOpcode(self: *const Assembler, mnemonic: []const u8) !Opcode {
        _ = self;
        const info = std.meta.fields(Opcode);
        inline for (info) |f| {
            if (std.mem.eql(u8, f.name, mnemonic)) return @enumFromInt(f.value);
        }
        return error.UnknownMnemonic;
    }

    fn parseRegister(self: *const Assembler, text: []const u8) !u8 {
        _ = self;
        // R0, r0, R123, etc.
        return try std.fmt.parseInt(u8, text[1..], 10);
    }

    fn parseImmediate(self: *const Assembler, text: []const u8) !u64 {
        _ = self;
        if (text.len > 1 and text[0] == '"') return 0; // Handled in directive
        if (std.mem.startsWith(u8, text, "0x") or std.mem.startsWith(u8, text, "0X")) {
            return try std.fmt.parseInt(u64, text[2..], 16);
        }
        return try std.fmt.parseInt(u64, text, 10);
    }

    fn parseF64(self: *const Assembler, text: []const u8) !f64 {
        _ = self;
        return try std.fmt.parseFloat(f64, text);
    }
};
