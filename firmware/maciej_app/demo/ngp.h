/* SNK Neo Geo Pocket & Neo Geo Pocket Color (.ngp / .ngc) emulator */
#ifndef DEMO_NGP_H
#define DEMO_NGP_H

#define NGP_W        160
#define NGP_H        152
#define NGP_FRAME_US 16742u   /* 59.73 Hz (6.144 MHz / (515 * 199)) */

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;

void ngp_set_bios(const u8 *data, u32 size);
const char *ngp_load(const u8 *data, u32 size);
const char *ngp_info(void);
void ngp_frame(u16 pad, u16 *picture);      /* 160 x 152 15-bit BGR555 */
int ngp_jammed(void);
u8 *ngp_save_ram(u32 *size, int *battery);
int ngp_save_changed(void);
void ngp_audio_rate(u32 hz);
int ngp_audio(s16 *out, int max);

#endif
