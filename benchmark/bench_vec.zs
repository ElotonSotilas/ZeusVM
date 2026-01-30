.org 0
    JMP @start

.data
.org 8
iterations: .u64 10000000
idx_init:   .f64 1.0
            .f64 2.0
step:       .f64 2.0
            .f64 2.0

.org 128
start:
    LOAD R1, @iterations
    IXOR R2, R2, R2 ; scalar i = 0
    
    ; V3 = {0.0, 0.0} (sum)
    IXOR R10, R10, R10
    V128_SPLAT_F64 V3, R10
    
    ; V1 = {1.0, 2.0} (current indices)
    PTR_ADD R11, R0, @idx_init
    V128_LOAD V1, R11
    
    ; V2 = {2.0, 2.0} (step)
    PTR_ADD R11, R0, @step
    V128_LOAD V2, R11

loop:
    V128_F64x2_SQRT V0, V1
    V128_F64x2_ADD V3, V3, V0
    V128_F64x2_ADD V1, V1, V2
    
    PTR_ADD R2, R2, 2
    ICMP_LT R6, R2, R1
    BR_IF @loop, R6
    
    HALT
