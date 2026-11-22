/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef FB_INTERNAL_H
#define FB_INTERNAL_H

#include "fb.h"

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

/* Console state (fb_text.c). */
extern int cursor_x;
extern int cursor_y;
extern uint32_t current_fb_color;

/* Framebuffer state (fb.c). */
extern uint32_t* fb_buffer;
extern uint32_t  fb_width;
extern uint32_t  fb_height;
extern uint32_t  fb_pitch;
extern uint8_t   fb_bpp;
extern uint8_t   fb_bytespp;

/* Shadow buffer state (fb.c). */
extern uint32_t* fb_shadow;
extern uint8_t*  fb_dirty_row;
extern uint32_t  fb_dirty_y_min;
extern uint32_t  fb_dirty_y_max;
extern int       fb_shadow_armed;

/* Drawing-path helpers (fb.c). */
uint32_t* fb_render_buf(void);
void fb_mark_dirty_row(uint32_t y);
void fb_mark_dirty_rows(uint32_t y0, uint32_t y1);

/* Pack a 0xRRGGBB colour into the framebuffer's native pixel format, using
 * the channel layout the bootloader reported. */
uint32_t fb_pack_color(uint32_t rgb);

/* Store one packed pixel at `p`, writing exactly fb_bytespp bytes.  Defined
 * here (not in fb.c) so the rasteriser and the drawing primitives share one
 * inlined code path for every pixel depth.  The 2- and 4-byte depths emit a
 * single native-size store instead of assembling the pixel byte by byte;
 * __builtin_memcpy keeps that a legal unaligned store rather than a type-punned
 * one.  always_inline matters because the kernel builds without -O, where a
 * plain `static inline` is still a call per pixel — the byte loop it replaces
 * is exactly what makes the console crawl. */
__attribute__((always_inline)) static inline void fb_store_pixel(uint8_t* p, uint32_t px) {
    switch (fb_bytespp) {
    case 1:
        p[0] = (uint8_t)px;
        break;
    case 2: {
        uint16_t v = (uint16_t)px;
        __builtin_memcpy(p, &v, sizeof(v));
        break;
    }
    case 3:
        p[0] = (uint8_t)px;
        p[1] = (uint8_t)(px >> 8);
        p[2] = (uint8_t)(px >> 16);
        break;
    default: {  /* 4 */
        uint32_t v = px;
        __builtin_memcpy(p, &v, sizeof(v));
        break;
    }
    }
}

/* Glyph rasteriser (fb_text.c).  Set glyph pixels take `fg`, cleared ones take
 * `bg`; a non-black `bg` is what fills a cell for SGR 7 (reverse video). */
void fb_draw_char_scaled(char c, int px, int py, uint32_t fg, uint32_t bg);

#endif
