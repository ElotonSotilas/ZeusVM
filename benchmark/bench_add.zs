.org 0
    JMP @start

.data
.org 8
iterations: .u64 100000000
one: .f64 1.0

.org 128
start:
    LOAD R1, @iterations
    IXOR R2, R2, R2
    PTR_ADD R10, R0, @one
    LOAD R10, R10
loop:
    PTR_ADD R2, R2, 1
    FADD R3, R3, R10
    ICMP_LT R6, R2, R1
    BR_IF @loop, R6
    HALT
