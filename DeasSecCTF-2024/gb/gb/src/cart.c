#include "cart.h"
#include <stdio.h>

void load_cart(cart_t* cart, char* filename){
    FILE* fp;
    char log[0x30];
    memset(log, 0, 0x30);
    snprintf(log, 0x2e, "Cart: %s", filename);
    LOG(INFO, log);
    fp = fopen(filename, "r");
    if(!fp) {
        LOG(ERROR, "failed to open file");
        exit(1);
    }


    fseek(fp, 0x100, SEEK_SET);
    fread(&cart->entry, 0x4, 1, fp);
    fread(&cart->logo, 0x30, 1, fp);
    fread(&cart->title, 0x10, 1, fp);

    memset(log, 0, 0x30);
    snprintf(log, 0x2e, "Title: %s", cart->title);
    LOG(INFO, log);

    fseek(fp, 0x13F, SEEK_SET);
    fread(&cart->manufacturer_code, 0x4, 1, fp);
    fread(&cart->CGB_flag, 1, 1, fp);
    fread(&cart->new_licensee_code, 2, 1, fp);
    fread(&cart->SBG_flag, 1, 1, fp);
    fread(&cart->cart_type, 1, 1, fp);
    fread(&cart->num_ROM, 1, 1, fp);
    fread(&cart->val_RAM, 1, 1, fp);
    fread(&cart->dest_code, 1, 1, fp);
    fread(&cart->old_licensee_code, 1, 1, fp);
    fread(&cart->mask_rom_version_numer, 1, 1, fp);
    fread(&cart->header_checksum, 1, 1, fp);
    fread(&cart->global_checksum, 2, 1, fp);

#ifdef TEST
    cart->val_RAM = 2; //for now patch in RAM
#endif

    fclose(fp);

    return;
}

//determine the type of cartridge and set mapper functions
void select_mapper(uint8_t cart_type, mapper_t *mapper){
    switch(cart_type){
        case ROM_ONLY:
            LOG(INFO, "Cart type is ROM_ONLY");
            //no need to assign a mapper function in this case
            mapper->read = read_rom_only;
            mapper->write = write_rom_only;
            break;
        case MBC1:
            LOG(INFO, "Cart type is MBC1");
            mapper->read = read_MBC1;
            mapper->write = write_MBC1;
            break;
        case MBC1_RAM:
        case MBC1_RAM_BATTERY:
        case MBC2:
        case MBC2_BATTERY:
        case ROM_RAM:
        case ROM_RAM_BATTERY:
        case MMM01:
        case MMM01_RAM:
        case MMM01_RAM_BATTERY:
        case MBC3_TIMER_BATTERY:
        case MBC3_TIMER_RAM_BATTERY:
        case MBC3:
        case MBC3_RAM:
        case MBC3_RAM_BATTERY:
        case MBC5:
        case MBC5_RAM:
        case MBC5_RAM_BATTERY:
        case MBC5_RUMBLE:
        case MBC5_RUMBLE_RAM:
        case MBC5_RUMBLE_RAM_BATTERY:
        case MBC6:
        case MBC7_SENSOR_RUMBLE_RAM_BATTERY:
        case POCKET_CAMERA:
        case BANDAI_TAMA5:
        case HuC3:
        case HuC1_RAM_BATTERY:
            LOGF(ERROR, "Cartridge 0x%x not supported\n", cart_type);
            exit(1);
        default:
            LOGF(ERROR, "Cartridge 0x%x not recognized", cart_type);
            exit(1);
        }
}

