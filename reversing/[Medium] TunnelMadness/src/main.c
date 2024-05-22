#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>

#include "maze.h"

#include "maze.inc"

#if 0
void print_pos(struct coord* pos) {
    printf("{ %u, %u, %u }", pos->x, pos->y, pos->z);
}

void print_cell(struct cell* cell) {
    print_pos(&cell->pos);
    #define V(name) \
        case name: \
            printf(": " #name); \
            break;
    switch (cell->cell_type) {
        V(START);
        V(OPEN);
        V(CLOSED);
        V(FINISH);
    }
    #undef V
}
#else
#define print_pos(x)
#define print_cell(x)
#endif

const struct cell* get_cell(struct coord* pos) {
    return &maze[pos->x][pos->y][pos->z];
}

void prompt_and_update_pos(struct coord* pos) {
    char inp;
    printf("Direction (L/R/F/B/U/D/Q)? ");
    if (scanf(" %c", &inp) != 1) {
        exit(-1);
    }
    inp = toupper(inp);
    struct coord tmp = *pos;

    #define V(dir, coord_field, limit, op) \
        case dir: {\
            if (pos->coord_field == limit) { \
                puts("Cannot move that way"); \
                return; \
            } \
            (tmp.coord_field)op; \
            if (get_cell(&tmp)->cell_type == CLOSED) { \
                puts("Cannot move that way"); \
                return; \
            } \
            *pos = tmp; \
            break; \
        }

    #define VV(coord, down, up) \
        V(down, coord, 0, --); \
        V(up, coord, MAZE_SIZE-1, ++);

    switch (inp) {
        VV(x, 'L', 'R');
        VV(y, 'B', 'F');
        VV(z, 'D', 'U');
        case 'Q':
            puts("Goodbye!");
            exit(-2);
    }
    #undef V
    #undef VV
}

void get_flag() {
    FILE* file = fopen("/flag.txt", "r");
    if (!file) {
        puts("HTB{fake_flag_for_testing}");
    } else {
        char buf[128] = { 0 };
        fgets(buf, sizeof(buf), file);
        puts(buf);
        fclose(file);
    }
}

int main() {
    struct coord pos = {
        0, 0, 0
    };
    char inp;
    while (get_cell(&pos)->cell_type != FINISH) {
        print_pos(&pos);
        putchar('\n');
        prompt_and_update_pos(&pos);
    }
    puts("You break into the vault and read the secrets within...");
    get_flag();
}
