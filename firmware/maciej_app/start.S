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

/* Restart through the original bootloader.

   First a full chip reset by the watchdog (the SDK's dog_m3327e at
   0xB8018500: count at +0, control byte at +4), armed as the M3801 loaders'
   own 'reboot' arms it: 0xFFFFF000, then 0x67 (reset mode, running, the
   slowest prescaler), which overflows within milliseconds.  It resets the
   whole chip as at power-on -- also the display engine, VCAP and USB, which
   otherwise keep reading and writing RAM while the loader reinitializes the
   DRAM: on a real S3811 box the jump below hung once the demo's 'video init'
   had them running.  The emulator has no watchdog: when no reset has come
   after about 0.3 s (100 M CP0 Count ticks) the watchdog is stopped again
   and the old path follows, with the OSD layer switched off first.

   That path is the exact M3801/S3811 branch of this dump's
   sys_watchdog_reboot and sys_ic_reboot (flash offsets 0xf6f8 and 0xf5e4).
   Despite the SDK name, it uses a peripheral reset pulse and a jump to the
   flash vector; it does not program a watchdog. The loader recognizes
   $s8=0xdeadbead, reinitializes DRAM/cache, copies its code, and installs
   its own stack. This profile is only for the loader protected by
   maciej_image's hash. */
    .globl platform_restart
    .ent platform_restart
platform_restart:
    mfc0    $t0, $12                       /* interrupts off */
    nop
    nop
    nop
    addiu   $t1, $zero, -2
    and     $t0, $t0, $t1
    mtc0    $t0, $12
    nop
    nop
    nop
    lui     $t0, 0xb801                    /* the watchdog */
    ori     $t0, $t0, 0x8500
    lui     $t1, 0xffff
    ori     $t1, $t1, 0xf000
    sw      $t1, 0($t0)                    /* count: 0x1000 ticks before it overflows */
    addiu   $t1, $zero, 0x67
    sb      $t1, 4($t0)                    /* reset mode, run, prescaler 3 */
    mfc0    $t2, $9
    lui     $t4, 0x05f5
    ori     $t4, $t4, 0xe100               /* 100,000,000 Count ticks */
1:
    mfc0    $t3, $9
    nop
    subu    $t3, $t3, $t2
    sltu    $t3, $t3, $t4
    bnez    $t3, 1b
    nop
    sb      $zero, 4($t0)                  /* no reset came: the watchdog off again */
    lui     $t0, 0xb800
    sw      $zero, 0x6300($t0)             /* the OSD layer off */

    lui     $s8, 0xdead
    ori     $s8, $s8, 0xbead
    move    $s7, $zero
    move    $s5, $zero

    /* Restore the same SPI controller mode used by the original reset. */
    lui     $t0, 0xb800
    lui     $t1, 0x0200
    ori     $t1, $t1, 0x0d03
    sw      $t1, 0x0098($t0)

    mfc0    $t0, $12
    nop
    nop
    nop
    addiu   $t1, $zero, -2
    and     $t0, $t0, $t1
    mtc0    $t0, $12
    lui     $t0, 0xb800
    sw      $zero, 0x003c($t0)
    addiu   $t1, $zero, 0x01ff
    sw      $t1, 0x0060($t0)
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    move    $t1, $zero
    sw      $t1, 0x0060($t0)
    lui     $v0, 0xbfc0
    jr      $v0
    nop
    .end platform_restart
