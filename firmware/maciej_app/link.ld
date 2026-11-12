OUTPUT_ARCH(mips)
ENTRY(_start)

MEMORY {
    ram (rwx) : ORIGIN = 0x80000200, LENGTH = 0x007ffe00
}

SECTIONS {
    .text : { KEEP(*(.text.start)) *(.text .text.*) } > ram
    .rodata : { *(.rodata .rodata.*) } > ram
    .data : { *(.data .data.*) *(.sdata .sdata.*) } > ram
    .bss (NOLOAD) : {
        /* Keep the bounds inside the output section: >ram has its own
           placement cursor and can ignore an alignment outside it. */
        . = ALIGN(16);
        __bss_start = .;
        *(.bss .bss.*) *(.sbss .sbss.*) *(COMMON)
        . = ALIGN(4);
        __bss_end = .;
    } > ram
    _gp = __bss_start + 0x7ff0;
    ASSERT(__bss_start >= ADDR(.bss) && __bss_end == ADDR(.bss) + SIZEOF(.bss), "invalid BSS bounds")
    __stack_top = ORIGIN(ram) + LENGTH(ram);
    ASSERT(__bss_end < __stack_top - 0x10000, "application overlaps stack")
    /DISCARD/ : { *(.reginfo) *(.MIPS.abiflags) *(.pdr) *(.comment) *(.note*) *(.eh_frame*) }
}
