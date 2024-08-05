#ifndef LCD_H
#define LCD_H
#include "common.h"
#include "signal.h"
#include <stdint.h>
#include <sys/time.h>
#include <sys/ipc.h>
#include <sys/shm.h>

/*
 * my idea for this LCD class is to fork into a process that will consume writes from the
 * and display them to the window, by isolating the LCD I remove so of the timing restrictions
 * there might be to draw to the screen
 */
#define SCRN_WIDTH 160
#define SCRN_HEIGHT 144
#define BG_WIDTH 256
#define BG_HEIGHT 256
#define SCALE 3 //scale up the image to be a bit larger
#define FRAME_RATE 16666

typedef struct spt_data{
    uint8_t pixels[8];
    uint8_t X;
    uint8_t pallette;
    union{
        uint8_t sprite_flag;
        struct {
            uint8_t cgb_pallette: 3;
            uint8_t bank: 1;
            uint8_t DMG_pallette: 1;
            uint8_t X_flip: 1;
            uint8_t Y_flip: 1;
            uint8_t priority: 1;
        } flags;
    };
} sprite_t;

typedef struct {
    uint8_t bg_pixels[160];
    sprite_t spt_data[10];
    uint8_t num_spt;
} scanline;

/*
 * lcd_fifo_read: read side of the pipe, allows the lcd to work as a consumer
 * ppu: pointer to the ppu so I can change the STAT register if needbe
 */
typedef struct lcd_struct {
    _Atomic uint8_t spinlock;
    uint8_t BGP;
    union {
        uint8_t joycon;  
        struct{
            uint8_t A : 1;
            uint8_t B : 1;
            uint8_t Select : 1;
            uint8_t Start : 1;
            uint8_t sel_dpad : 1;
            uint8_t sel_buttons : 1;
            uint8_t unused : 2;
        };
    };
    uint8_t buttons;
    uint8_t d_pad;
    bool bg_to_obj;
    scanline lcd_data[144];
} LCD_t;



void init_lcd(int read_fd);
void lcd_loop();
#endif
