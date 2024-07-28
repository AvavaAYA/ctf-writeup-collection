#include <stdint.h>
#include "log.h"

//decorate error messages
uint8_t get_level(enum levels level){
    char ret; 
    switch(level){ 
        case ERROR: 
            ret = '!'; 
            break; 
        case WARN: 
            ret = '~'; 
            break; 
        case INFO: 
            ret = '*'; 
            break; 
        case DEBUG: 
            ret = '+'; 
            break; 
        default:
            ret = '*';
            break;
    }
    return ret;
}

