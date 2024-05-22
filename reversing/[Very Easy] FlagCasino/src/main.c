#include <stdlib.h>
#include <stdio.h>

#include "flag.inc"

const char banner[] = \
"     ,     ,\n"
"    (\\____/)\n"
"     (_oo_)\n"
"       (O)\n"
"     __||__    \\)\n"
"  []/______\\[] /\n"
"  / \\______/ \\/\n"
" /    /__\\\n"
"(\\   /____\\\n"
"---------------------";

int main() {
    puts("[ ** WELCOME TO ROBO CASINO **]");
    puts(banner);
    puts("[*** PLEASE PLACE YOUR BETS ***]");
    char inp;
    for (int i = 0; i < sizeof(check)/sizeof(check[0]); i++) {
        printf("> ");
        if (scanf(" %c", &inp) != 1) exit(-1);
        srand(inp);
        if (rand() == check[i]) {
            puts("[ * CORRECT *]");
        } else {
            puts("[ * INCORRECT * ]");
            puts("[ *** ACTIVATING SECURITY SYSTEM - PLEASE VACATE *** ]");
            exit(-2);
        }
    }
    puts("[ ** HOUSE BALANCE $0 - PLEASE COME BACK LATER ** ]");
}