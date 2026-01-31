; Vector Extension Test (V512 and V2048)
.org 0x00

    ; --- V512 Test ---
    ; 1. Setup data in memory
    PTR_ADD R1, R0, @data_v512_a
    V512_LOAD Z0, R1
    
    PTR_ADD R1, R0, @data_v512_b
    V512_LOAD Z1, R1

    ; 2. Z2 = Z0 + Z1
    V512_ADD Z2, Z0, Z1

    ; 3. Store result
    PTR_ADD R1, R0, @result_v512
    V512_STORE Z2, R1

    ; 4. Shuffle Test (V512)
    V512_SHUFFLE Z5, Z0, Z1

    ; --- V2048 Test ---
    ; 1. Setup data
    PTR_ADD R2, R0, @data_v2048_a
    V2048_LOAD X0, R2
    
    PTR_ADD R2, R0, @data_v2048_b
    V2048_LOAD X1, R2

    ; 2. X2 = X0 ^ X1
    V2048_XOR X2, X0, X1

    ; 3. Store result
    PTR_ADD R2, R0, @result_v2048
    V2048_STORE X2, R2

    ; 4. Shuffle Test (V2048)
    V2048_SHUFFLE X3, X0, X1

    ; --- F64 Parallel Test (V512) ---
    ; 1. Splat 1.23 to Z3
    PTR_ADD R5, R0, @val_f64
    LOAD R6, R5
    V512_SPLAT_F64 Z3, R6
    
    ; 2. Z4 = sqrt(Z3)
    V512_F64x8_SQRT Z4, Z3

    ; Verification (Manual for now, but we check if it runs)
    ; Print some status
    PTR_ADD R10, R0, @msg_ok
    STDOUT_WRITE R10, 15

    HALT

.org 0x200
data_v512_a:  .u64 0x0101010101010101, 0, 0, 0, 0, 0, 0, 0
data_v512_b:  .u64 0x0101010101010101, 0, 0, 0, 0, 0, 0, 0
result_v512:  .org 0x280

data_v2048_a: .u64 0xAAAAAAAAAAAAAAAA, 0, 0, 0, 0, 0, 0, 0
              .u64 0, 0, 0, 0, 0, 0, 0, 0
              .u64 0, 0, 0, 0, 0, 0, 0, 0
              .u64 0, 0, 0, 0, 0, 0, 0, 0
data_v2048_b: .u64 0x5555555555555555, 0, 0, 0, 0, 0, 0, 0
              .u64 0, 0, 0, 0, 0, 0, 0, 0
              .u64 0, 0, 0, 0, 0, 0, 0, 0
              .u64 0, 0, 0, 0, 0, 0, 0, 0
result_v2048: .org 0x500

val_f64: .f64 1.23
msg_ok: .string "Vector Test OK\n"
