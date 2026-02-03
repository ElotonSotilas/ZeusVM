; Special Floating Point Test (Infinity and NaN)
.org 0x00
    ; Load 1.0 and 0.0
    FADD R1, R0, @one
    FADD R2, R0, @zero
    FDIV R3, R1, R2 ; R3 should be inf

    ; Load inf directly
    FADD R4, R0, @L_inf_val
    ; Check if R3 == R4
    FCMP_EQ R5, R3, R4 ; R5 should be 1
    
    ; Load nan
    FADD R6, R0, @L_nan_val
    ; nan + 1.0 is nan
    FADD R7, R6, R1
    ; nan != nan should be 1
    FCMP_NE R8, R7, R7 ; R8 should be 1

    ; Verify results and print OK if all good
    ICMP_EQ R9, R5, 1
    ICMP_EQ R10, R8, 1
    IAND R11, R9, R10
    
    ; If R11 is 1, print Success
    PTR_ADD R12, R0, @L_msg_success
    STDOUT_WRITE R12
    HALT

.org 0x100
one: .f64 1.0
zero: .f64 0.0
L_inf_val: .f64 inf
L_nan_val: .f64 nan
L_msg_success: .string "Special Floating Point Test Success\n"
