//! ZeusVM - A language- and OS-agnostic virtual machine.
//!
//! POSIX-free design. Library-first approach.
//! Works on custom and bare metal OS kernels.

pub const bootstrap = @import("core/bootstrap.zig");
pub const opcode = @import("core/opcode.zig");
pub const vm = @import("backend/vm.zig");
pub const assembler = @import("core/assembler.zig");
