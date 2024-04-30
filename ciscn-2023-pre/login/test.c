#include <stdio.h>

void menu() {
    puts("Welcome to Q-CMS");
    puts("1. Register");
    puts("2. Login");
    puts("3. Forget PASSWD");
    puts("4. Quit");
    puts("> ");
}
int main() {
    int choice;

    while (1) {
        scanf("%d", &choice);
        if (choice == 1) {
            puts("Permission denied");
        }
        else if (choice == 2) {
            puts("Welcome to Q-CMS, you are login as admin now");
        }
    }
}
