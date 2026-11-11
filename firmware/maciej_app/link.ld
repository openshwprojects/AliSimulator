OUTPUT_ARCH(mips)
ENTRY(_start)

MEMORY {
    ram (rwx) : ORIGIN = 0x80000200, LENGTH = 0x007ffe00
}

SECTIONS {
    .text : { KEEP(*(.text.start)) *(.text .text.*) } > ram
    .rodata : { *(.rodata .rodata.*) } > ram
    .data : { *(.data .data.*) *(.sdata .sdata.*) } > ram
    . = ALIGN(16);
    _gp = . + 0x7ff0;
    __bss_start = .;
    .bss (NOLOAD) : { *(.bss .bss.*) *(.sbss .sbss.*) *(COMMON) . = ALIGN(4); } > ram
    __bss_end = .;
    __stack_top = ORIGIN(ram) + LENGTH(ram);
    ASSERT(__bss_end < __stack_top - 0x10000, "application overlaps stack")
    /DISCARD/ : { *(.reginfo) *(.MIPS.abiflags) *(.pdr) *(.comment) *(.note*) *(.eh_frame*) }
}
