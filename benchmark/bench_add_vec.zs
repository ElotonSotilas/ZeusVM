.org 0
    JMP @start

.data
.org 8
iterations: .u64 100000000
ones: .f64 1.0
      .f64 1.0

.org 128
start:
    LOAD R1, @iterations
    IXOR R2, R2, R2
    PTR_ADD R11, R0, @ones
    V128_LOAD V2, R11
loop:
    PTR_ADD R2, R2, 2
    V128_F64x2_ADD V3, V3, V2
    ICMP_LT R6, R2, R1
    BR_IF @loop, R6
    HALT
