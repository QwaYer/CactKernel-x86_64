/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#include "fb.h"
#include "fb_internal.h"
#include "font.h"
#include "klib.h"
#include "memory.h"
#include "serial.h"
#include "kernel.h"
#include "klog.h"
#include "sync.h"
#include <stddef.h>
#include <stdarg.h>

int cursor_x = 0;
int cursor_y = 0;

uint32_t saved_color = COLOR_WHITE;

/* CSI parser + SGR state, kept across console_puts() calls: tty_write() feeds
 * long buffers to the console in 255-byte chunks, and a chunk boundary must
 * not split an escape sequence nor lose the colour/reverse it set.  Guarded by
 * console_lock (held by console_puts()/console_replay()); console_replay()
 * resets it before a repaint so a VT replay starts from a clean state. */
static int esc_state = 0;      /* 0 = text, 1 = saw ESC, 2 = inside CSI */
static int esc_params[4];
static int esc_np;
static int esc_val;
static int esc_has_val;
static int saved_rev = 0;

/* Serialises console text rendering across CPUs (cursor + framebuffer state). */
static irq_spinlock_t console_lock;

uint32_t fb_char_cell_w(void) {
    const console_font_t *f = font_get_active();
    return (f ? f->width : 8u) * (uint32_t)FB_CONSOLE_FONT_SCALE;
}

uint32_t fb_char_cell_h(void) {
    const console_font_t *f = font_get_active();
    return (f ? f->height : 8u) * (uint32_t)FB_CONSOLE_FONT_SCALE;
}

/* Rasterise one glyph from the active PSF2 font at (px, py) into the shadow
 * (or, when the shadow is inactive, the real framebuffer).  Each glyph row is
 * expanded `scale` times horizontally and stamped down `scale` times.  Set
 * pixels take `fg`, cleared pixels take `bg`, so a non-black `bg` paints the
 * whole cell — the primitive behind SGR 7 (reverse video). */
void fb_draw_char_scaled(char c, int px, int py, uint32_t fg, uint32_t bg) {
    const console_font_t *f = font_get_active();
    if (unlikely(!f)) return;

    const uint32_t scale = (uint32_t)FB_CONSOLE_FONT_SCALE;
    const uint32_t fw    = f->width;
    const uint32_t fh    = f->height;
    const uint32_t out_w = fw * scale;
    const uint32_t out_h = fh * scale;

    /* scanline[] below is sized for CONSOLE_FONT_MAX_WIDTH; the PSF2 parser
     * enforces that limit, but a wider active font would otherwise overflow
     * the stack buffer here. */
    if (unlikely(fw > CONSOLE_FONT_MAX_WIDTH)) return;

    if (unlikely(px < 0 || py < 0))              return;
    if (unlikely((uint32_t)px + out_w > fb_width))  return;
    if (unlikely((uint32_t)py + out_h > fb_height)) return;

    int gi = font_glyph_index(f, (uint32_t)(uint8_t)c);
    if (unlikely(gi < 0)) return;

    const uint8_t *glyph = font_glyph_bits(f, (uint32_t)gi);
    if (unlikely(!glyph)) return;

    uint32_t bpp = fb_bytespp;
    if (unlikely(bpp == 0)) return;

    uint32_t* buf = fb_render_buf();
    if (unlikely(!buf)) return;

    const uint32_t fg_px = fb_pack_color(fg);
    const uint32_t bg_px = fb_pack_color(bg);

    uint32_t scanline[CONSOLE_FONT_MAX_WIDTH * FB_CONSOLE_FONT_SCALE];

    uint8_t* const base_row = (uint8_t*)buf + (size_t)py * (size_t)fb_pitch
                            + (size_t)px * (size_t)bpp;

    for (uint32_t row = 0; row < fh; row++) {
        const uint8_t *rb = glyph + (size_t)row * (size_t)f->bytes_per_row;

        for (uint32_t col = 0; col < fw; col++) {
            uint8_t  mask = (uint8_t)(0x80u >> (col & 7u));
            uint32_t v    = (rb[col >> 3] & mask) ? fg_px : bg_px;
            uint32_t *sp  = &scanline[col * scale];
            for (uint32_t k = 0; k < scale; k++)
                sp[k] = v;
        }

        for (uint32_t s = 0; s < scale; s++) {
            uint8_t* d = base_row + (size_t)(row * scale + s) * (size_t)fb_pitch;
            for (uint32_t c = 0; c < out_w; c++) {
                fb_store_pixel(d, scanline[c]);
                d += bpp;
            }
        }
    }

    fb_mark_dirty_rows((uint32_t)py, (uint32_t)py + out_h);
}

void clear_screen(void) {
    fb_clear(COLOR_BLACK);
    cursor_x = 0;
    cursor_y = 0;
}

void scroll(void) {
    uint32_t w = fb_width;
    uint32_t h = fb_height;
    uint32_t* buf = fb_render_buf();
    if (unlikely(!buf || w == 0 || h == 0))
        return;

    uint32_t shift = fb_char_cell_h();
    if (unlikely(shift >= h))
        return;

    uint8_t* base = (uint8_t*)buf;
    uint32_t bytes = (h - shift) * fb_pitch;
    /* dst < src, so a forward byte copy is safe. */
    memcpy(base, base + (size_t)shift * (size_t)fb_pitch, bytes);

    fb_fill_rect(0, h - shift, w, shift, COLOR_BLACK);

    fb_mark_dirty_rows(0, h);

    cursor_y -= (int)shift;
    if (cursor_y < 0)
        cursor_y = 0;
}

static const uint32_t ansi_colors[16] = {
    COLOR_BLACK, COLOR_RED, COLOR_GREEN, 0xAAAA00,
    COLOR_BLUE, COLOR_MAGENTA, COLOR_CYAN, COLOR_LIGHT_GREY,
    COLOR_DARK_GREY, COLOR_LIGHT_RED, COLOR_LIGHT_GREEN, COLOR_LIGHT_BROWN,
    COLOR_LIGHT_BLUE, COLOR_LIGHT_MAGENTA, COLOR_LIGHT_CYAN, COLOR_WHITE,
};

/* Raw console renderer: framebuffer (or, with no display, serial) only.
 * The kernel message log is fed by printk()/printk_color(), not from here. */
static void _console_emit(const char* message, uint32_t len, uint32_t color,
                          int to_serial) {
    uint32_t w = fb_get_width();
    uint32_t h = fb_get_height();
    int have_fb = (w != 0 && h != 0);

    /* saved_color/saved_rev are the live terminal attributes: they persist
     * across console_puts() calls and change only on SGR — the per-call `color`
     * argument is a base used when a reset (SGR 0) asks for one.  A VT repaint
     * clears them (console_replay()). */

    if (unlikely(!have_fb)) {
        if (!to_serial) return;
        for (uint32_t i = 0; i < len; i++) {
            char c = message[i];
            if (!c) break;
            serial_putc(c);
        }
        return;
    }

    uint32_t cellw = fb_char_cell_w();
    uint32_t cellh = fb_char_cell_h();
    if (unlikely(cellw == 0 || cellh == 0))
        return;

    uint32_t max_x = w - cellw;
    uint32_t max_y = h - cellh;

    for (uint32_t i = 0; i < len; i++) {
        char c = message[i];
        if (!c) break;

        if (esc_state == 0) {
            /* ordinary text */
            if (c == '\033') {
                if (to_serial) serial_putc(c);
                esc_state = 1;
                continue;
            }
            if (to_serial) serial_putc(c);
            if (c == '\n') {
                cursor_x = 0;
                cursor_y += (int)cellh;
            } else if (c == '\r') {
                cursor_x = 0;
            } else if (c == '\t') {
                int tab_w = (int)cellw * 4;
                cursor_x = (cursor_x / tab_w + 1) * tab_w;
            } else {
                fb_draw_char_scaled(c, cursor_x, cursor_y,
                                    saved_rev ? COLOR_BLACK : saved_color,
                                    saved_rev ? saved_color : COLOR_BLACK);
                cursor_x += (int)cellw;
            }

            if ((uint32_t)cursor_x > max_x) {
                cursor_x = 0;
                cursor_y += (int)cellh;
            }
            if ((uint32_t)cursor_y > max_y) {
                scroll();
            }
            continue;
        }

        if (esc_state == 1) {
            /* right after ESC: it must be a CSI introducer */
            if (to_serial) serial_putc(c);
            if (c == '[') {
                esc_state = 2;
                esc_np = 0; esc_val = 0; esc_has_val = 0;
            } else {
                esc_state = 0;
            }
            continue;
        }

        /* esc_state == 2: inside CSI, collecting parameters.  The state lives
         * in the statics above, so a chunk boundary here resumes cleanly. */
        if (c >= '0' && c <= '9') {
            if (to_serial) serial_putc(c);
            /* Cap the accumulator: a long digit run would otherwise overflow
             * int before the parameter is clamped below. */
            if (esc_val < 100000) esc_val = esc_val * 10 + (c - '0');
            esc_has_val = 1;
            continue;
        }
        if (c == ';') {
            if (to_serial) serial_putc(c);
            /* params[] is fixed at 4: a CSI with more parameters (any program
             * can emit one) must not index past it — that is a kernel-stack
             * write reachable from userspace.  Extra parameters are dropped. */
            if (esc_np < 4) esc_params[esc_np++] = esc_has_val ? esc_val : 0;
            esc_val = 0; esc_has_val = 0;
            continue;
        }

        /* final byte of the CSI */
        if (to_serial) serial_putc(c);
        if (esc_has_val && esc_np < 4) esc_params[esc_np++] = esc_val;
        esc_state = 0;

        if (c == 'm') {
            /* A bare ESC[m carries no parameter and is SGR 0 (reset) per ANSI;
             * treat it like an explicit 0. */
            if (esc_np == 0) {
                saved_color = color;
                saved_rev = 0;
            }
            for (int p = 0; p < esc_np; p++) {
                if (esc_params[p] >= 30 && esc_params[p] <= 37)
                    saved_color = ansi_colors[esc_params[p] - 30];
                else if (esc_params[p] >= 90 && esc_params[p] <= 97)
                    saved_color = ansi_colors[8 + esc_params[p] - 90];
                else if (esc_params[p] == 7)
                    saved_rev = 1;
                else if (esc_params[p] == 27)
                    saved_rev = 0;
                else if (esc_params[p] == 0) {
                    saved_color = color;
                    saved_rev = 0;
                }
            }
        } else if (c == 'H') {
            int row = (esc_np > 0 && esc_params[0] > 0) ? esc_params[0] : 1;
            int col = (esc_np > 1 && esc_params[1] > 0) ? esc_params[1] : 1;
            /* Clamp to the last on-screen cell BEFORE the multiply:
             * (row-1)*cellh overflows int for a hostile row, and a cursor
             * parked past the screen can never be drawn back into view. */
            uint32_t rows = h / cellh;
            uint32_t cols = w / cellw;
            if (rows == 0) rows = 1;
            if (cols == 0) cols = 1;
            if ((uint32_t)row > rows) row = (int)rows;
            if ((uint32_t)col > cols) col = (int)cols;
            cursor_y = (row - 1) * (int)cellh;
            cursor_x = (col - 1) * (int)cellw;
        } else if (c == 'A' || c == 'B' || c == 'C' || c == 'D') {
            /* Relative cursor movement (CUU/CUD/CUF/CUB), default count 1.
             * Move in whole cells, clamping the count to the room actually
             * available so a hostile parameter cannot overflow the pixel
             * offset or push the cursor off screen. */
            uint32_t rows = h / cellh;
            uint32_t cols = w / cellw;
            if (rows == 0) rows = 1;
            if (cols == 0) cols = 1;
            uint32_t n = (esc_np > 0 && esc_params[0] > 0) ? (uint32_t)esc_params[0] : 1u;
            uint32_t row = (uint32_t)cursor_y / cellh;
            uint32_t col = (uint32_t)cursor_x / cellw;
            if (c == 'A') {
                if (n > row) n = row;
                cursor_y -= (int)(n * cellh);
            } else if (c == 'B') {
                if (n > rows - 1 - row) n = rows - 1 - row;
                cursor_y += (int)(n * cellh);
            } else if (c == 'C') {
                if (n > cols - 1 - col) n = cols - 1 - col;
                cursor_x += (int)(n * cellw);
            } else {
                if (n > col) n = col;
                cursor_x -= (int)(n * cellw);
            }
        } else if (c == 'J') {
            int mode = (esc_np > 0) ? esc_params[0] : 0;
            if (mode == 2) {
                clear_screen();
            } else if (mode == 0) {
                uint32_t fy = (uint32_t)cursor_y;
                uint32_t fx = (uint32_t)cursor_x;
                while ((int)fy <= (int)max_y) {
                    uint32_t sx = (fy == (uint32_t)cursor_y) ? fx : 0;
                    fb_fill_rect(sx, fy, w - sx, cellh, COLOR_BLACK);
                    fy += cellh;
                }
                fb_mark_dirty_rows((uint32_t)cursor_y, h);
            }
        } else if (c == 'K') {
            /* EL — erase in line: 0 = cursor..end, 1 = start..cursor
             * (inclusive), 2 = the whole row.  fb_mark_dirty_rows() takes
             * scanlines (pixels), not cell indices. */
            int mode = (esc_np > 0) ? esc_params[0] : 0;
            uint32_t sy = (uint32_t)cursor_y;
            if (mode == 1) {
                fb_fill_rect(0, sy, (uint32_t)cursor_x + cellw,
                             cellh, COLOR_BLACK);
            } else if (mode == 2) {
                fb_fill_rect(0, sy, w, cellh, COLOR_BLACK);
            } else {
                uint32_t sx = (uint32_t)cursor_x;
                fb_fill_rect(sx, sy, w - sx, cellh, COLOR_BLACK);
            }
            fb_mark_dirty_rows(sy, sy + cellh);
        }

        esc_np = 0; esc_val = 0; esc_has_val = 0;
    }

    fb_flush();
}

/* Public console sinks.  console_puts() is the normal one (framebuffer plus
 * serial mirror); console_replay() draws to the framebuffer only, so a VT
 * repaint does not push a screenful of old text down the serial line.
 *
 * console_puts() also feeds console_on_write(), which the tty core uses to keep
 * the active VT's scrollback in sync with what was actually drawn — that is how
 * kernel messages survive a VT switch.  console_replay() deliberately skips it
 * so repainting a terminal does not duplicate its own history. */
void console_puts(char* message, uint32_t color) {
    uint32_t len = strlen(message);
    /* Serialise console rendering across CPUs: the cursor position and the
     * framebuffer text state are shared, and tty scrolling depends on the
     * writes arriving whole. */
    irq_spinlock_acquire(&console_lock);
    console_on_write(message, len);
    _console_emit(message, len, color, 1);
    irq_spinlock_release(&console_lock);
}

void console_replay(const char* message, uint32_t len, uint32_t color) {
    irq_spinlock_acquire(&console_lock);
    /* A repaint starts a fresh byte stream: drop any half-parsed escape and the
     * SGR state the live stream left behind. */
    esc_state = 0;
    esc_np = 0;
    esc_val = 0;
    esc_has_val = 0;
    saved_rev = 0;
    _console_emit(message, len, color, 0);
    irq_spinlock_release(&console_lock);
}

/* Kernel log lines carry their level colour in `color`.  The console keeps SGR
 * state across writes (tty_write() chunks them), so prepend an SGR reset: the
 * reset adopts this line's colour and clears whatever the userspace stream left
 * set.  Only the console stream gets the escape — klog_feed()/dev/kmsg get the
 * clean text. */
static void console_puts_log(char* message, uint32_t color) {
    char rst[] = "\033[0m";
    console_puts(rst, color);
    console_puts(message, color);
}

/* Console line with no explicit level: render it and log it at the default
 * level.  Kept for callers that already have a rendered string. */
void printk_color(char* message, uint32_t color) {
    klog_feed(KLOG_LEVEL_DEFAULT, message, strlen(message));
    if (KLOG_LEVEL_DEFAULT <= console_loglevel_get())
        console_puts_log(message, color);
}

/* Same as printk_color(), but the text enters the log at `level`. */
void printk_color_level(int level, char* message, uint32_t color) {
    klog_feed(level, message, strlen(message));
    if (level <= console_loglevel_get())
        console_puts_log(message, color);
}

// Linux-style printk: format string with optional KERN_<level> prefix.
// The level sets the console colour and travels into the kernel log; without
// a prefix the message is logged at KLOG_LEVEL_DEFAULT (KERN_INFO).
void printk(const char* fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);

    uint32_t color = COLOR_WHITE;
    int level = KLOG_LEVEL_DEFAULT;
    if (fmt[0] == '\x01' && fmt[1] >= '0' && fmt[1] <= '7') {
        level = fmt[1] - '0';
        switch (fmt[1]) {
        case '0': color = COLOR_LIGHT_RED;    break; // KERN_EMERG
        case '1': color = COLOR_LIGHT_RED;    break; // KERN_ALERT
        case '2': color = COLOR_LIGHT_RED;    break; // KERN_CRIT
        case '3': color = COLOR_LIGHT_RED;    break; // KERN_ERR
        case '4': color = COLOR_LIGHT_BROWN;  break; // KERN_WARNING
        case '5': color = COLOR_WHITE;        break; // KERN_NOTICE
        case '6': color = COLOR_LIGHT_GREY;   break; // KERN_INFO
        case '7': color = COLOR_DARK_GREY;    break; // KERN_DEBUG
        }
        fmt += 2;
    }

    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    klog_feed(level, buf, strlen(buf));
    if (level <= console_loglevel_get())
        console_puts_log(buf, color);
}

void init_framebuffer(void) {
    fb_init_result_t status = fb_get_init_status();

    if (status != FB_INIT_OK) {
        static const char* fb_errors[] = {
            [FB_INIT_NO_FLAG]    = "multiboot2 framebuffer tag missing",
            [FB_INIT_HIGH_ADDR]  = "framebuffer address above 4 GB (not mappable)",
            [FB_INIT_BAD_TYPE]   = "framebuffer type != 1 (not RGB direct-color)",
            [FB_INIT_BAD_BPP]    = "unsupported pixel depth (need 8/15/16/24/32 bpp)",
            [FB_INIT_NULL_PARAM] = "null address or zero width/height",
            [FB_INIT_BAD_PITCH]  = "pitch smaller than one scanline of pixels",
        };
        pr_err("%s: %s\n", "framebuffer", fb_errors[status]);
        pr_crit("%s: cannot continue without display\n", "framebuffer");
        return;
    }
    /* Success line (geometry / PAT / shadow) is printed once by kernel.c. */
}
