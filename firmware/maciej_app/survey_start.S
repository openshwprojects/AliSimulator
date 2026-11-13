/* Entry of the flash survey's test application (hello.c,
   tools/bootloader_flash_survey.py): start.S's start-up, but it runs
   wherever a bootloader unpacks and starts the main code.  Most loaders use
   the chunk's load address -- 0x80000200 when the header leaves it
   0xFFFFFFFF -- but some builds have their own default (the Amiko / Amstar
   M3602 loaders unpack and start the main code at 0x80008000).  The code
   finds where it runs (bal), copies itself to the address it was linked for
   when that differs, writes the copy back from the data cache, invalidates
   it in the instruction cache, and goes on there. */
    .set noreorder
    .set noat
    .section .text.start, "ax", @progbits
    .globl _start
    .ent _start
_start:
    /* Mask interrupts before replacing the loader's stack (as start.S). */
    mfc0    $t0, $12
    lui     $t1, 0xffff
    ori     $t1, $t1, 0x00fe
    and     $t0, $t0, $t1
    mtc0    $t0, $12
    nop
    nop
    nop
    bal     1f                  /* $ra: where label 1 runs */
    nop
1:
    la      $t2, 1b             /* where it was linked */
    beq     $ra, $t2, 6f        /* in place: nothing to move */
    subu    $t3, $ra, $t2       /* (delay slot) run - link */
    la      $t0, _start         /* destination: the link address */
    addu    $t1, $t0, $t3       /* source: where the loader put it */
    la      $t4, __bss_start    /* the image ends where .bss begins */
    subu    $t5, $t4, $t0       /* image size, a multiple of 4 */
    sltu    $t6, $t1, $t0
    bnez    $t6, 3f             /* source below destination: copy downwards */
    nop
2:                              /* upwards (destination below source) */
    beqz    $t5, 5f
    nop
    lw      $t7, 0($t1)
    sw      $t7, 0($t0)
    addiu   $t1, $t1, 4
    addiu   $t0, $t0, 4
    b       2b
    addiu   $t5, $t5, -4
3:                              /* downwards, from the end */
    addu    $t0, $t0, $t5
    addu    $t1, $t1, $t5
4:
    beqz    $t5, 5f
    nop
    addiu   $t0, $t0, -4
    addiu   $t1, $t1, -4
    lw      $t7, 0($t1)
    sw      $t7, 0($t0)
    b       4b
    addiu   $t5, $t5, -4
5:
    la      $t0, _start         /* the new copy: out of the data cache, */
    la      $t4, __bss_start    /* stale lines out of the instruction cache */
7:
    cache   0x15, 0($t0)        /* Hit_Writeback_Inv_D */
    cache   0x10, 0($t0)        /* Hit_Invalidate_I */
    sltu    $t6, $t0, $t4
    bnez    $t6, 7b
    addiu   $t0, $t0, 16
    sync
    la      $t0, 6f             /* continue in the copy */
    jr      $t0
    nop
6:
    la      $sp, __stack_top
    la      $gp, _gp
    la      $t0, __bss_start
    la      $t1, __bss_end
8:
    beq     $t0, $t1, 9f
    nop
    sw      $zero, 0($t0)
    b       8b
    addiu   $t0, $t0, 4
9:
    jal     app_main
    nop
10:
    b       10b
    nop
    .end _start
