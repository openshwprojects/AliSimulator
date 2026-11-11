/* RAM entry called by the original Opticum N2 bootloader. */
    .set noreorder
    .set noat
    .section .text.start, "ax", @progbits
    .globl _start
    .ent _start
_start:
    /* The bootloader has already initialized DRAM and the UART clock.
       Mask interrupts before replacing its stack or exception state. */
    mfc0    $t0, $12
    lui     $t1, 0xffff
    ori     $t1, $t1, 0x00fe
    and     $t0, $t0, $t1
    mtc0    $t0, $12
    nop
    nop
    nop
    la      $sp, __stack_top
    la      $gp, _gp
    la      $t0, __bss_start
    la      $t1, __bss_end
1:
    beq     $t0, $t1, 2f
    nop
    sw      $zero, 0($t0)
    b       1b
    addiu   $t0, $t0, 4
2:
    jal     app_main
    nop
3:
    b       3b
    nop
    .end _start
