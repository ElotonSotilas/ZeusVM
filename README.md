# ZeusVM

A powerful, language- and OS-agnostic Virtual Machine designed for high performance and portability. ZeusVM features a sophisticated JIT compiler, a comprehensive SIMD-ready ISA, and built-in support for threading, networking, and filesystem operations.

## Architecture Overview

ZeusVM is a register-based virtual machine with the following core components:

### 1. Registers
- **General Purpose Registers (`R0-R255`)**: 64-bit scalar registers. 
  - `R0` is typically used as a zero-constant in logic, but it is general-purpose (writable).
  - **JIT Mapping**: `R0-R4` are mapped directly to host CPU registers (`rbx`, `r12`, `r13`, `r14`, `r15`) for maximum performance.
- **Vector Registers (`V0-V255`)**: Polymorphic dynamic registers for parallel processing.
  - **Dynamic Sizing**: Registers are dynamically allocated and zero-padded to the nearest power of two.
  - **JIT Mapping**: Large vectors are processed via high-performance SIMD intrinsics.

### 2. Memory & Stack
- **Linear Memory**: A language-agnostic byte array. Size is configurable via CLI (default 1MB).
- **Stack**: A dedicated 64-bit value stack used for `CALL`/`RET` and temporary data storage.

---

## Zeus Assembly (`.zs`)

Programs are written in Zeus Assembly and assembled into 64-bit Big-Endian instructions.

### Syntax
- **Instructions**: `MNEMONIC [Rd], [Rs1], [Rs2], [Immediate]`
- **Labels**: Defined with `name:` and referenced with `@name`.
- **Comments**: Start with `;`.
- **Floating-Point Literals**: Supports `inf`, `infinity`, and `nan` (case-insensitive).

### Directives
| Directive | Description |
| :--- | :--- |
| `.org <addr>` | Sets the assembly cursor to a specific absolute address. |
| `.u64 <val>` | Emits a 64-bit unsigned integer (supports hex `0x...`). |
| `.f64 <val>` | Emits a 64-bit floating-point number (supports `inf`, `nan`). |
| `.string "..."` | Emits a null-terminated string. Supports escapes like `\n`. |

---

## CLI Reference

### Basic Usage
```bash
# Assemble and Run
zig build run -- program.zs --run

# Assemble to Binary (.zeus)
zig build run -- program.zs -o output.zeus

# Run Binary
zig build run -- program.zeus
```

### Flags
- `-m, --mem <size>`: Set memory size (e.g., `2MB`, `512KB`, `1GB`).
- `--jit-threshold <n>`: Set JIT hotness threshold (Default: `50`).
- `--no-jit`: Disable JIT and use the interpreter only.
- `--run`: Force execution after assembling a `.zs` file.

---

## Instruction Set Reference (ISA)

All instructions are encoded as 64-bit Big-Endian words: `[Opcode:8][Rd:8][Rs1:8][Rs2:8][Immediate:32]`

### 1. Control Flow
| Mnemonic | Opcode | Description |
| :--- | :--- | :--- |
| `NOP` | 0x00 | No operation. |
| `HALT` | 0x01 | Terminate VM execution. |
| `JMP @addr` | 0x02 | Jump to absolute address. |
| `BR Rs1, @addr` | 0x03 | Relative branch. |
| `BR_IF Rs1, @addr` | 0x04 | Branch to address if `Rs1 != 0`. |
| `CALL Rd, @addr` | 0x05 | Push PC+8 to stack and jump to address. Stays for compatibility; `Rd` is reserved. |
| `RET` | 0x06 | Pop address from stack and jump. |
| `CALL_REG Rs1` | 0x0F | Indirect call to address stored in `Rs1`. |

### 2. Integer Arithmetic
| Mnemonic | Opcode | Description |
| :--- | :--- | :--- |
| `IADD Rd, Rs1, Rs2` | 0x10 | `Rd = Rs1 + Rs2` |
| `ISUB Rd, Rs1, Rs2` | 0x11 | `Rd = Rs1 - Rs2` |
| `IMUL Rd, Rs1, Rs2` | 0x12 | `Rd = Rs1 * Rs2` |
| `IDIV Rd, Rs1, Rs2` | 0x13 | `Rd = Rs1 / Rs2` |
| `IMOD Rd, Rs1, Rs2` | 0x14 | `Rd = Rs1 % Rs2` |
| `IAND Rd, Rs1, Rs2` | 0x15 | `Rd = Rs1 & Rs2` |
| `IOR  Rd, Rs1, Rs2` | 0x16 | `Rd = Rs1 | Rs2` |
| `IXOR Rd, Rs1, Rs2` | 0x17 | `Rd = Rs1 ^ Rs2` |
| `ISHL Rd, Rs1, Rs2` | 0x18 | `Rd = Rs1 << Rs2` |
| `ISHR Rd, Rs1, Rs2` | 0x19 | `Rd = Rs1 >> Rs2` |

### 3. Memory & Pointers
| Mnemonic | Opcode | Description |
| :--- | :--- | :--- |
| `LOAD Rd, Rs1, Imm` | 0x20 | `Rd = mem[Rs1 + Imm]` (64-bit Big-Endian). |
| `STORE Rs1, Rs2, Imm` | 0x21 | `mem[Rs2 + Imm] = Rs1` (64-bit Big-Endian). |
| `MEM_COPY Rd, Rs1, Rs2`| 0x22 | Copy `Rs2` bytes from `mem[Rs1]` to `mem[Rd]`. |
| `MEM_ZERO Rd, Rs2` | 0x23 | Zero `Rs2` bytes starting at `mem[Rd]`. |
| `HEAP_ALLOC Rd, Rs1` | 0x24 | Allocate `Rs1` bytes on host heap, pointer in `Rd`. |
| `HEAP_FREE Rs1` | 0x25 | Free host heap allocation at address `Rs1`. |
| `PTR_ADD Rd, Rs1, Imm` | 0x26 | `Rd = Rs1 + Imm` (Immediate arithmetic). |
| `PTR_SUB Rd, Rs1, Imm` | 0x27 | `Rd = Rs1 - Imm` (Immediate arithmetic). |

### 4. Comparison
| Mnemonic | Opcode | Description |
| :--- | :--- | :--- |
| `ICMP_EQ Rd, Rs1, Rs2` | 0x30 | `Rd = (Rs1 == Rs2) ? 1 : 0` |
| `ICMP_NE Rd, Rs1, Rs2` | 0x31 | `Rd = (Rs1 != Rs2) ? 1 : 0` |
| `ICMP_LT Rd, Rs1, Rs2` | 0x32 | `Rd = (Rs1 < Rs2) ? 1 : 0` |
| `ICMP_GT Rd, Rs1, Rs2` | 0x33 | `Rd = (Rs1 > Rs2) ? 1 : 0` |
| `ICMP_LE Rd, Rs1, Rs2` | 0x34 | `Rd = (Rs1 <= Rs2) ? 1 : 0` |
| `ICMP_GE Rd, Rs1, Rs2` | 0x35 | `Rd = (Rs1 >= Rs2) ? 1 : 0` |

### 5. Host & Threading
| Mnemonic | Opcode | Description |
| :--- | :--- | :--- |
| `TIME_NOW Rd` | 0x40 | Get monotonic nanoseconds into `Rd`. |
| `SLEEP_NS Rs1` | 0x41 | Sleep for `Rs1` nanoseconds. |
| `THREAD_SPAWN Rd, Rs1`| 0x42 | Spawn thread at address `Rs1`, thread handle in `Rd`. |
| `THREAD_JOIN Rs1` | 0x43 | Join thread handle `Rs1`. |
| `THREAD_YIELD` | 0x44 | Yield current thread execution. |

### 6. Filesystem
| Mnemonic | Opcode | Description |
| :--- | :--- | :--- |
| `FS_OPEN Rd, Rs1, Rs2` | 0x48 | Open file at path `Rs1`, flags `Rs2`, handle in `Rd`. |
| `FS_READ Rd, Rs1, Rs2` | 0x49 | Read `Rs2` bytes from handle `Rs1` into buffer `Rd`. |
| `FS_WRITE Rd, Rs1, Rs2`| 0x4A | Write `Rs2` bytes to handle `Rs1` from buffer `Rd`. |
| `FS_CLOSE Rs1` | 0x4B | Close file handle `Rs1`. |
| `FS_SIZE Rd, Rs1` | 0x4C | Get size of file handle `Rs1` into `Rd`. |
| `FS_SEEK Rs1, Rs2` | 0x4D | Seek file handle `Rs1` to absolute position `Rs2`. |
| `FS_MKDIR Rs1` | 0x4E | Create directory (and parents) at path `Rs1`. |
| `FS_REMOVE Rs1` | 0x4F | Recursively delete file/directory at path `Rs1`. |

### 7. Modules & Standard I/O
| Mnemonic | Opcode | Description |
| :--- | :--- | :--- |
| `LOAD_MODULE Rs1` | 0x50 | Load a dynamic `.zeus` module from path `Rs1`. |
| `STDIN_READ Rd, Rs1, Imm` | 0x51 | Read up to `Imm` bytes from STDIN into buffer `Rs1`, count in `Rd`. |
| `STDOUT_WRITE Rs1, Imm` | 0x52 | Write `Imm` bytes from buffer `Rs1` to STDOUT. |
| `STDERR_WRITE Rs1, Imm` | 0x53 | Write `Imm` bytes from buffer `Rs1` to STDERR. |

### 8. Networking
| Mnemonic | Opcode | Description |
| :--- | :--- | :--- |
| `NET_OPEN Rd, Rs1, Rs2` | 0x54 | Connect to IP `Rs1`, port `Rs2`, handle in `Rd`. |
| `NET_CLOSE Rs1` | 0x55 | Close network handle `Rs1`. |
| `NET_SEND Rd, Rs1, Rs2` | 0x56 | Send `Rs2` bytes from buffer `Rd` via handle `Rs1`. |
| `NET_RECV Rd, Rs1, Rs2` | 0x57 | Receive `Rs2` bytes into buffer `Rd` from handle `Rs1`. |
| `NET_POLL Rd, Rs1, Rs2` | 0x58 | Poll handle `Rs1` for events mask `Rs2`. |
| `NET_LISTEN Rd, Rs1, Rs2`| 0x59 | Bind and listen on port `Rs2` (IP `Rs1`), handle in `Rd`. |
| `NET_ACCEPT Rd, Rs1` | 0x5A | Accept connection from listener `Rs1`, client handle in `Rd`. |

### 9. Dynamic Vectors

ZeusVM supports polymorphic SIMD (Single Instruction, Multiple Data) operations. Vector registers are dynamically sized based on the instruction's length immediate.

#### Register Format
- `Vn`: A vector register (0-255).
- `Len`: A 32-bit immediate specifying the number of bytes to operate on.

> [!NOTE]
> The VM automatically pads vector memory to the nearest power of two for optimal cache alignment and SIMD performance.

#### Vector Instructions
| Mnemonic | Opcode | Description |
| :--- | :--- | :--- |
| `V_LOAD Vd, Rs1, Len` | 0x60 | Load `Len` bytes from `mem[Rs1]` into `Vd`. |
| `V_STORE Vd, Rs1, Len` | 0x61 | Store `Len` bytes from `Vd` into `mem[Rs1]`. |
| `V_ADD Vd, Va, Vb, Len` | 0x62 | Parallel 8-bit integer addition. |
| `V_SUB Vd, Va, Vb, Len` | 0x63 | Parallel 8-bit integer subtraction. |
| `V_MUL Vd, Va, Vb, Len` | 0x64 | Parallel 8-bit integer multiplication. |
| `V_AND Vd, Va, Vb, Len` | 0x65 | Bitwise AND. |
| `V_OR  Vd, Va, Vb, Len` | 0x66 | Bitwise OR. |
| `V_XOR Vd, Va, Vb, Len` | 0x67 | Bitwise XOR. |
| `V_FADD Vd, Va, Vb, Len` | 0x69 | Parallel F64 addition. |
| `V_FSUB Vd, Va, Vb, Len` | 0x6A | Parallel F64 subtraction. |
| `V_FMUL Vd, Va, Vb, Len` | 0x6B | Parallel F64 multiplication. |
| `V_FDIV Vd, Va, Vb, Len` | 0x6C | Parallel F64 division. |
| `V_FSQRT Vd, Va, Len` | 0x6D | Parallel F64 square root. |
| `V_SPLAT Vd, Rs1, Len` | 0x6E | Broadcast 64-bit value from `Rs1` to all 8-byte lanes in `Len`. |
| `V_SHUFFLE Vd, Va, Vb, Len`| 0x68 | Shuffle bytes (Implementation specific). |

### 10. Atomic Operations (SEQ_CST)
All atomic operations require **8-byte alignment**.
| Mnemonic | Opcode | Description |
| :--- | :--- | :--- |
| `ATOMIC_LOAD Rd, Rs1` | 0x70 | Atomic 64-bit load from `mem[Rs1]`. |
| `ATOMIC_STORE Rs1, Rs2`| 0x71 | Atomic 64-bit store of `Rs1` to `mem[Rs2]`. |
| `ATOMIC_RMW Rd, Rs1, Rs2`| 0x72 | Atomic fetch-and-ADD: `Rd = [Rs1]; [Rs1] += Rs2`. |
| `ATOMIC_CAS Rd, Rs1, Rs2`| 0x73 | Atomic Compare-and-Swap: `if [Rs1] == Rs2 { [Rs1] = Rd; Rd = old_val; }`. |

### 11. Floating Point (F64)
| Mnemonic | Opcode | Description |
| :--- | :--- | :--- |
| `FADD Rd, Rs1, Rs2` | 0x80 | Double-precision addition. |
| `FSUB Rd, Rs1, Rs2` | 0x81 | Double-precision subtraction. |
| `FMUL Rd, Rs1, Rs2` | 0x82 | Double-precision multiplication. |
| `FDIV Rd, Rs1, Rs2` | 0x83 | Double-precision division. |
| `FNEG Rd, Rs1` | 0x84 | `Rd = -Rs1` |
| `FABS Rd, Rs1` | 0x85 | `Rd = \|Rs1\|` |
| `FSQRT Rd, Rs1` | 0x86 | Double-precision square root. |
| `FCMP_EQ Rd, Rs1, Rs2` | 0x90 | `Rd = (Rs1 == Rs2) ? 1 : 0`. |
| `FCMP_NE Rd, Rs1, Rs2` | 0x91 | `Rd = (Rs1 != Rs2) ? 1 : 0`. |
| `FCMP_LT Rd, Rs1, Rs2` | 0x92 | `Rd = (Rs1 < Rs2) ? 1 : 0`. |
| `FCMP_GT Rd, Rs1, Rs2` | 0x93 | `Rd = (Rs1 > Rs2) ? 1 : 0`. |
| `FCMP_LE Rd, Rs1, Rs2` | 0x94 | `Rd = (Rs1 <= Rs2) ? 1 : 0`. |
| `FCMP_GE Rd, Rs1, Rs2` | 0x95 | `Rd = (Rs1 >= Rs2) ? 1 : 0`. |
| `FCONV_I2F Rd, Rs1` | 0xA0 | Convert integer `Rs1` to float `Rd`. |
| `FCONV_F2I Rd, Rs1` | 0xA1 | Convert float `Rs1` to integer `Rd`. |

### 12. Dynamic Library (DL / FFI)
| Mnemonic | Opcode | Description |
| :--- | :--- | :--- |
| `DL_OPEN Rd, Rs1` | 0xB0 | Open library at path `Rs1` (null-terminated string), handle in `Rd`. |
| `DL_SYM Rd, Rs1, Rs2` | 0xB1 | Lookup symbol `Rs2` (string) in handle `Rs1`, address in `Rd`. |
| `DL_CALL Rd, Rs1, Rs2` | 0xB2 | Call FFI function at `Rs1` with `ArgBlock` at `Rs2`, result in `Rd`. |
| `DL_CLOSE Rs1` | 0xB3 | Close library handle `Rs1`. |

**ArgBlock Encoding**: `[count:64][type_mask:64][arg0:64][arg1:64]...` (Big-Endian).
`type_mask`: 2 bits per arg (00=u64, 01=f64, 10=ptr).

---

## Deployment & Archives (`.zar`)

Zeus Archives (`.zar`) are portable packages containing multiple files. When executed:
1.  The archive is extracted to a temporary hidden directory (`.zeus_tmp_<timestamp>`).
2.  `main.zeus` is automatically loaded and executed.
3.  The temporary directory is cleaned up upon VM termination.

---

## JIT Compiler

The ZeusVM JIT dynamically identifies hot code blocks and loops to compile them into native x86-64 machine code.

- **Dynamic Deoptimization**: If the JIT fails to compile a complex block, it safely falls back to the interpreter.
- **Register Pinning**: To eliminate the overhead of VM state access, the most active registers (`R0-R4`, `V0-V3`) are pinned to host hardware registers during JIT execution.
