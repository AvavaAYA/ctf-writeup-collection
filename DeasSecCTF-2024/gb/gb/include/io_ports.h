#ifndef IO_PORTS
#define IO_PORTS
#include <common.h>

typedef byte(*read_io)();
typedef void(*write_io)(byte);

#define NUM_REGS 0x20

typedef struct io_struct{
    struct io_struct *next;
    address addr;
    read_io read_callback;
    write_io write_callback;
} io_reg;

enum {
    JOYP    = 0xFF00,
    SB	    = 0xFF01,
    SC	    = 0xFF02,
    DIV	    = 0xFF04,
    TIMA	= 0xFF05,
    TMA	    = 0xFF06,
    TAC	    = 0xFF07,
    IF	    = 0xFF0F,
    NR10	= 0xFF10,
    NR11	= 0xFF11,
    NR12	= 0xFF12,
    NR13	= 0xFF13,
    NR14	= 0xFF14,
    NR21	= 0xFF16,
    NR22	= 0xFF17,
    NR23	= 0xFF18,
    NR24	= 0xFF19,
    NR30	= 0xFF1A,
    NR31	= 0xFF1B,
    NR32	= 0xFF1C,
    NR33	= 0xFF1D,
    NR34	= 0xFF1E,
    NR41	= 0xFF20,
    NR42	= 0xFF21,
    NR43	= 0xFF22,
    NR44	= 0xFF23,
    NR50	= 0xFF24,
    NR51	= 0xFF25,
    NR52	= 0xFF26,
    WAV_RAM	= 0xFF30,
    LCDC	= 0xFF40,
    STAT	= 0xFF41,
    SCY	    = 0xFF42,
    SCX	    = 0xFF43,
    LY	    = 0xFF44,
    LYC	    = 0xFF45,
    DMA	    = 0xFF46,
    BGP	    = 0xFF47,
    OBP0	= 0xFF48,
    OBP1	= 0xFF49,
    WY	    = 0xFF4A,
    WX	    = 0xFF4B,
    KEY1	= 0xFF4D,
    VBK	    = 0xFF4F,
    HDMA1	= 0xFF51,
    HDMA2	= 0xFF52,
    HDMA3	= 0xFF53,
    HDMA4	= 0xFF54,
    HDMA5	= 0xFF55,
    RP	    = 0xFF56,
    BCPS    = 0xFF68,
    BCPD    = 0xFF69,
    OCPS    = 0xFF6A,
    OCPD    = 0xDFF6B,
    OPRI	= 0xFF6C,
    SVBK	= 0xFF70,
    PCM12	= 0xFF76,
    PCM34	= 0xFF77,
    IE      = 0xFFFF
};

byte read_SB();
void write_SB(byte data);
void write_SC(byte data);

#endif
