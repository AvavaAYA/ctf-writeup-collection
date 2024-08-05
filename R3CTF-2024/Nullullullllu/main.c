#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>

void menu(){
    puts("Hello Nullullullllu!");
    puts("1. Give me a memory!");
    puts("2. Give me a null!");
    puts("3. End!");
}

int main(){
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);

    bool first = true;
    char choose = 0;
    char *mem = 0;

    menu();

    while(true){
        printf("> ");
        choose = getchar();
        while(getchar()!='\n'){}
        switch(choose){
            case '1':
                printf("libc_base = %p\n", (&puts-0x87bd0));
                break;
            case '2':
                if(first){
                    printf("Mem: ");
                    scanf("%llx", (long long unsigned int*)&mem);
                    printf("One byte Null is in %p\n", mem);
                    *mem = 0;
                    first = 0;
                } else {
                    puts("I said that give me \"a\" null ~");
                }
                break;
            case '3':
                exit(1);
                break;
        }
    }
    return 0;
}
