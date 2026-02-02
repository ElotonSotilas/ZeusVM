; FS Test - Testing new filesystem instructions
.org 0x00

    ; 1. Create directory "fs_test_dir"
    PTR_ADD R1, R0, @path_dir
    FS_MKDIR R1

    ; 2. Open "fs_test_dir/file.txt" for reading(1) + writing(2) + create(4) = 7
    PTR_ADD R2, R0, @path_file
    PTR_ADD R3, R0, 7 ; flags: read(1) | write(2) | create(4) = 7
    FS_OPEN R4, R2, R3

    ; 3. Write "Hello ZeusFS!" (Rd: R12, Rs1: handle R4, Rs2: buf R5, Imm: 13)
    PTR_ADD R5, R0, @content
    FS_WRITE R12, R4, R5, 13

    ; 4. Get file size
    FS_SIZE R7, R4
    ; Check if R7 == 13
    PTR_ADD R14, R0, 13
    ICMP_EQ R8, R7, R14
    BR_IF R8, @size_ok
    HALT ; failed if size not 13
size_ok:

    ; 5. Seek to 6
    PTR_ADD R9, R0, 6
    FS_SEEK R4, R9

    ; 6. Read back "ZeusFS!" - use a scratch buffer in memory
    PTR_ADD R10, R0, @scratch
    FS_READ R13, R4, R10, 7

    ; 7. Write to STDOUT to verify
    STDOUT_WRITE R10, 7
    
    ; 8. Close and remove
    FS_CLOSE R4
    PTR_ADD R1, R0, @path_dir
    FS_REMOVE R1 ; removes "fs_test_dir"

    HALT

.org 0x200
path_dir:  .string "fs_test_dir"
path_file: .string "fs_test_dir/file.txt"
content:   .string "Hello ZeusFS!"
scratch:   .org 0x300 ; reserve some space
