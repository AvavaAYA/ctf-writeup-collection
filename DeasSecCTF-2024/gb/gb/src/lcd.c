#include "lcd.h"
#include <poll.h>
#include <raylib.h>
#include <stdint.h>
#include <string.h>
#include <sys/shm.h>

LCD_t *lcd;

uint8_t screen[SCRN_HEIGHT][SCRN_WIDTH]; //store all information that is read from the ppu
                                         
void cleanup_lcd(int sig){
    LOG(INFO, "Cleaning up the LCD handler");
    shmdt(lcd);
    CloseWindow();
    exit(0);
}

//TODO create window for raylib, set a signal listener to kill the LCD process
void init_lcd(int shm_id){
    InitWindow(SCRN_WIDTH * SCALE, SCRN_HEIGHT * SCALE, "Game Boi");
    LOG(INFO, "LCD created");
    signal(SIGPIPE, cleanup_lcd); //set a cleanup listener
    lcd = shmat(shm_id, NULL, 0);
    if(lcd == (void *)-1){
        perror("shmat");
        exit(0);
    }

    //init lcd data;
    while(lcd->spinlock);
    lcd->spinlock = 1;
    memset(lcd->lcd_data, 0, sizeof(scanline) * 144);
    lcd->bg_to_obj = false;
    lcd->BGP = 0;
    lcd->spinlock = 0;

    return;
}

void color_correct(uint8_t *pix, uint8_t pallette){
    *pix = (pallette >> (*pix * 2)) & 3;
}

//bg_to_obj is only necessary for gameboy color
void merge(uint8_t x, uint8_t y, uint8_t obj_pix, bool priority){
    uint8_t bg_pix, merged;

    merged = 0;

    if(x < 8 || x > 168)
        return;

    bg_pix = screen[y][x-8];

    screen[y][x-8] = merged;
    if(priority){
        if(bg_pix > 0){
            merged = bg_pix;
        } else {
            merged = obj_pix;
        }
    } else {
        if(obj_pix > 0){
            merged = obj_pix;
        } else {
            merged = bg_pix;
        }
    }

    screen[y][x-8] = merged;
}


void parse_line(scanline *line, uint8_t y){
    uint8_t obj_pix, bg_pix, i, j;
    sprite_t sprite;

    //color correct and store background data;
    for(i = 0; i < 160; i++){
        bg_pix = line->bg_pixels[i];
        color_correct(&bg_pix, lcd->BGP);
        screen[y][i] = bg_pix;
    }

    for(i = 0; i < line->num_spt; i++){
        memcpy(&sprite, &line->spt_data[i], sizeof(sprite_t));
        for(j = 0; j < 8; j++){
            obj_pix = sprite.flags.X_flip ? sprite.pixels[7-j] : sprite.pixels[j];
            color_correct(&obj_pix, sprite.pallette);
            merge(sprite.X + j, y, obj_pix, sprite.flags.priority);
        }
    }
}

void draw_grid(){
    uint64_t i;

    for(i = 0; i < 20; i++)
        DrawLine((i * 8) * SCALE, 0, (i * 8) * SCALE, 144 * SCALE, RED);

    for(i = 0; i < 18; i++)
        DrawLine(0, (i * 8) * SCALE, 160 * SCALE, (i * 8) * SCALE, RED);
}

void render_screen(){
    uint8_t pix;
    for(uint64_t i = 0; i < SCRN_HEIGHT; i++){
        for(uint64_t j = 0; j < SCRN_WIDTH; j++){
            pix = screen[i][j];
            //TODO fetch the color from the pixel stored at that location
            switch(pix){
                case 0:
                    DrawRectangle(j * SCALE, i * SCALE, SCALE, SCALE, WHITE);
                    break;
                case 1:
                    DrawRectangle(j * SCALE, i * SCALE, SCALE, SCALE, BLUE);
                    break;
                case 2:
                    DrawRectangle(j * SCALE, i * SCALE, SCALE, SCALE, DARKBLUE);
                    break;
                case 3:
                    DrawRectangle(j * SCALE, i * SCALE, SCALE, SCALE, BLACK);
                    break;
                default:
                    printf("error in lcd pix 0x%x\n", pix);
                    DrawRectangle(j * SCALE, i * SCALE, SCALE, SCALE, WHITE);
                    break;
            }
        }
    }
    //draw_grid();
}

void check_buttons(){
    uint8_t d_pad, buttons;
    d_pad = buttons = 0;

    buttons |= IsKeyDown(KEY_M) ? 0 : 1;
    buttons |= IsKeyDown(KEY_L) ? 0 : 2;
    buttons |= IsKeyDown(KEY_ENTER) ? 0 : 4;
    buttons |= IsKeyDown(KEY_SPACE) ? 0 : 8;

    d_pad |= IsKeyDown(KEY_D) ? 0 : 1;
    d_pad |= IsKeyDown(KEY_A) ? 0 : 2;
    d_pad |= IsKeyDown(KEY_W) ? 0 : 4;
    d_pad |= IsKeyDown(KEY_S) ? 0 : 8;

    lcd->buttons = buttons;
    lcd->d_pad = d_pad;
}

void lcd_loop(){
    SetTargetFPS(60);
    while(!WindowShouldClose()){
        while(lcd->spinlock);
        lcd->spinlock = 1;
        for(uint8_t i = 0; i < 144; i++)
            parse_line(&lcd->lcd_data[i], i);
        check_buttons();
        lcd->spinlock = 0;

        BeginDrawing();
        render_screen();
        EndDrawing();
    }
    cleanup_lcd(0);
}
