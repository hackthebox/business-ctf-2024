#include <stdio.h>
#include <unistd.h>

ssize_t send_satellite_message(unsigned int sat_id, const char* msg);

const char banner[] = 
"         ,-.\n"
"        / \\  `.  __..-,\e[31;1mO \e[5m\e[34;49;1m≈ ≈ ≈ ≈ ≈ ≈ ≈ ≈ ≈ ≈ ≈ ≈\e[0m\n"
"       :   \\ --''_..-'.'\n"
"       |    . .-' `. '.\n"
"       :     .     .`.'\n"
"        \\     `.  /  ..\n"
"        \\      `.   ' .\n"
"          `,       `.   \\\n"
"         ,|,`.        `-.\\\n"
"        '.||  ``-...__..-`\n"
"         |  |\n"
"         |__|\n"
"         /||\\\n"
"        //||\\\\\n"
"       // || \\\\\n"
"    __//__||__\\\\__\n"
"   '--------------' \n"
"| \e[32;1;4mREADY TO TRANSMIT\e[0m |";

int main() {
    setbuf(stdout, NULL);
    puts(banner);
    send_satellite_message(0, "START");
    char buf[1024] = { 0 };
    while (1) {
        putchar('>');
        putchar(' ');
        ssize_t val = read(1, buf, 1024);
        if (val < 0) {
            puts("ERROR READING DATA");
        } else {
            if (val >= 1) buf[val - 1] = 0;
            printf("Sending `%s`\n", buf);
            send_satellite_message(0, buf);
        }
    }
}