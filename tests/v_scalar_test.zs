; Vector-Scalar Test
.org 0x00

    ; --- Test V_IADDS ---
    PTR_ADD R1, R0, @data_v8_a
    V_LOAD V0, R1, 8
    
    ; Load scalar 10 into R2
    PTR_ADD R1, R0, @val_u8
    LOAD R2, R1
    
    ; V1 = V0 + R2 (scalar 10)
    V_IADDS V1, V0, R2, 8

    ; Store result
    PTR_ADD R1, R0, @result_v8
    V_STORE R1, V1, 8

    ; --- Test V_FADDS ---
    PTR_ADD R1, R0, @data_f64x2_a
    V_LOAD V3, R1, 16
    
    ; Load scalar 10.0 into R3
    PTR_ADD R1, R0, @val_f64
    LOAD R3, R1
    
    ; V4 = V3 + R3 (scalar 10.0)
    V_FADDS V4, V3, R3, 16

    ; Store result
    PTR_ADD R1, R0, @result_f64
    V_STORE R1, V4, 16

    ; Print OK
    PTR_ADD R10, R0, @msg_ok
    STDOUT_WRITE R10, 24

    HALT

.org 0x200
data_v8_a:    .u64 0x0102030405060708
val_u8:       .u64 0x0A ; 10
result_v8:    .org 0x220

data_f64x2_a: .f64 1.0, 2.0
val_f64:      .f64 10.0
result_f64:   .org 0x250

msg_ok: .string "Vector-Scalar Test OK\n"
