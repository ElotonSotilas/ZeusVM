; FFI Verification Test
; Loads libc and calls printf

.org 0x0
    JMP @start

.org 0x100
libc_path:
    .string "libc"

printf_sym:
    .string "printf"

fmt_str:
    .string "FFI Test: Int=%d, Float=%f\n"

arg_block:
    .u64 3              ; Count (fmt, int, float)
    .u64 0x12           ; TypeMask: arg[0]=ptr(10), arg[1]=int(00), arg[2]=float(01) = (01<<4)|(00<<2)|(10) = 0x12
    .u64 0              ; Arg0 (fmt_str pointer placeholder)
    .u64 123            ; Arg1 (int)
    .f64 3.14159        ; Arg2 (float)

handle:
    .u64 0
printf_addr:
    .u64 0

.org 0x200
start:
    ; 0. Initialize R0 to 0 (should already be 0 but let's be sure)
    IXOR R0, R0, R0
    
    ; 1. Load libc
    PTR_ADD R1, R0, @libc_path  ; R1 = address of libc_path string
    DL_OPEN R2, R1              ; R2 = library handle, R1 contains path
    PTR_ADD R10, R0, @handle
    STORE R2, R10, 0
    
    ; 2. Lookup printf
    PTR_ADD R3, R0, @printf_sym ; R3 = address of printf_sym string
    DL_SYM R4, R2, R3           ; R4 = printf address, R2=handle, R3=symbol name
    PTR_ADD R11, R0, @printf_addr
    STORE R4, R11, 0
    
    ; 3. Setup ArgBlock
    ; We need to put the address of fmt_str into the first slot of args
    PTR_ADD R5, R0, @fmt_str    ; R5 = &fmt_str
    PTR_ADD R6, R0, @arg_block  ; R6 = &arg_block
    STORE R5, R6, 16            ; Store R5 into arg_block[2] (Offset 16)
    
    ; 4. Call printf
    ; DL_CALL Ret, Addr, ArgBlock  
    DL_CALL R7, R4, R6
    
    HALT





