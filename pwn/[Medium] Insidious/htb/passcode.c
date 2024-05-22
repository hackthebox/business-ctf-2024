// this code is extracted from IDA decompilation.
#include <stdlib.h>
#include <time.h>
#include <stdio.h>

unsigned int passcode() {
    unsigned int v2;

    srand(time(0));

    for (int i = 0; i <=6; ++i)
        rand();
    
    v2 = rand();
    for (int j = rand() % 0x64; j; --j) {
        v2 = 27 * ((((32 * v2) ^ 0xf) >> 7) ^ 0x1f4); 
    }
    return v2;
}
