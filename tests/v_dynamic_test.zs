; Dynamic Vector Test
.org 0x00

    ; --- Test V_LOAD and V_STORE (Length 13) ---
    PTR_ADD R1, R0, @data_v13_a
    V_LOAD V0, R1, 13
    
    PTR_ADD R1, R0, @data_v13_b
    V_LOAD V1, R1, 13

    ; V2 = V0 + V1
    V_ADD V2, V0, V1, 13

    ; Store result (13 bytes)
    PTR_ADD R1, R0, @result_v13
    V_STORE R1, V2, 13

    ; --- Test V_FADD (Length 16, 2 doubles) ---
    PTR_ADD R1, R0, @data_f64x2_a
    V_LOAD V3, R1, 16
    
    PTR_ADD R1, R0, @data_f64x2_b
    V_LOAD V4, R1, 16

    V_FADD V5, V3, V4, 16

    PTR_ADD R1, R0, @result_f64
    V_STORE R1, V5, 16

    ; --- Test V_SPLAT ---
    PTR_ADD R1, R0, @val_f64
    LOAD R2, R1
    V_SPLAT V6, R2, 32 ; Splat to 32 bytes (4 doubles)

    ; Print OK
    PTR_ADD R10, R0, @msg_ok
    STDOUT_WRITE R10, 24

    HALT

.org 0x200
data_v13_a:   .u64 0x0101010101010101, 0x0101010101000000
data_v13_b:   .u64 0x0101010101010101, 0x0101010101000000
result_v13:   .org 0x250

data_f64x2_a: .f64 1.0, 2.0
data_f64x2_b: .f64 3.0, 4.0
result_f64:   .org 0x300

val_f64: .f64 1.23
msg_ok: .string "Dynamic Vector Test OK\n"
