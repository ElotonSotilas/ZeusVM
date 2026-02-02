.org 0
    JMP @start

.data
.org 8
iterations: .u64 10000000

.org 128
start:
    LOAD R1, @iterations
    IXOR R2, R2, R2 ; i = 0
    FCONV_I2F R3, R0 ; sum = 0.0

loop:
    PTR_ADD R2, R2, 1
    FCONV_I2F R4, R2
    FSQRT R5, R4
    FADD R3, R3, R5
    ICMP_LT R6, R2, R1
    BR_IF @loop, R6
    HALT
