<img src="../../../../../assets/banner.png" style="zoom: 80%;" align=center />

<img src="../../../../../assets/htb.png" style="zoom: 80%;" align='left' /><font size="6">TunnelMadness</font>

  22<sup>nd</sup> 04 22 / Document No. D24.102.59

  Prepared By: clubby789

  Challenge Author: clubby789

  Difficulty: <font color=orange>Medium</font>

  Classification: Official


# Synopsis

TunnelMadness is a Medium reversing challenge. Players must reverse engineer the format of an embedded 3-dimensional maze, then solve the maze to retrieve the flag.

## Skills Required
    - Decompiler usage
## Skills Learned
    - Use of Pwntools
    - Simple scripting

# Solution

If we run the provided binary, we're prompted with this:

```
Direction (L/R/F/B/U/D/Q)?
```

These seem to correspond to directions, with 'Q' acting as a 'Quit'.

```
Direction (L/R/F/B/U/D/Q)? L
Cannot move that way

Direction (L/R/F/B/U/D/Q)? R
Cannot move that way

Direction (L/R/F/B/U/D/Q)? U

Direction (L/R/F/B/U/D/Q)? Q
Goodbye!
```

## Analysis

Opening the binary in a decompiler, we'll start at `main`. Luckily, the binary is not stripped.


```c
int32_t main(int32_t argc, char** argv, char** envp)
  int32_t var_14 = 0
  int32_t var_10 = 0
  int32_t var_c = 0
  while (true) {
      if (*(get_cell(&var_14) + 0xc) == 3) {
          break
      }
      putchar(c: 0xa)
      prompt_and_update_pos(&var_14)
  }
  puts(str: "You break into the vault and read the secrets within...")
  get_flag()
  return 0
```

`get_cell` seems to use the given argument as a struct or array, and uses 3 integers to index into an array 'maze':

```c
struct struct_2* get_cell(struct struct_1* arg1_1)
  return ((zx.q(arg1_1->x) * 0x190 + zx.q(arg1_1->y) * 0x14 + zx.q(arg1_1->z)) << 4) + &maze
```

Given that other functions refer to a 'position', we can guess that these are 3 coordinates, used to index into a 3D array.

The index is calculated by taking `(x * 400) + (y * 20) + z`, then shifting it left by 4 (i.e. a multiplication by 16). We can assume then that this is an array of type `struct_2 maze[20][20][20]`, where `struct_2` is 16 bytes.

## Position Update

```c
uint64_t prompt_and_update_pos(struct struct_1* pos)
  printf(format: "Direction (L/R/F/B/U/D/Q)? ")
  char inp
  if (__isoc99_scanf(format: " %c", &inp) != 1) {
      exit(status: 0xffffffff)
      noreturn
  }
  int32_t rax_5 = (*__ctype_toupper_loc())[sx.q(inp)]
  inp = rax_5.b
  struct struct_1 tmp
  tmp.x = pos->x
  tmp.y = pos->y
  tmp.z = pos->z
```

What follows is a switch statement handling each input kind, like this:

```c
int32_t x = pos->x
if (x == 0) {
    z = puts(str: "Cannot move that way")
} else {
    tmp.x = x - 1
    if (get_cell(arg1_1: &tmp)->field_c == 2) {
        z = puts(str: "Cannot move that way")
    } else {
        struct struct_1 tmp2
        tmp2.d = tmp.x
        tmp2:4.d = tmp.y
        pos->x = tmp2.d
        pos->y = tmp2:4.d
        z = zx.q(tmp.z)
        pos->z = z.d
    }
}

```
We check if if the new X coordinate would be in bounds (cannot go left if X is 0 or right if X is 19).
We then check if the value of `field_c` is 2, and report that we cannot move that way if so. Otherwise, `pos` is updated.

Returning to `main`, this loops until `field_c` is 3. Looking into the `maze` array, we can see that the first entry (i.e. (0, 0, 0) where the player starts) has a `field_c` of 0. A few entries have a value of 1, most have a value of 2 and only 1 (19, 19, 19) has a value of 3.

We can assume from this that `0` indicates the start, `3` the end, `1` an open cell and `2` a wall.

## Solving

We'll write a solver that analyzes the binary to discover a path.

Let's import pwntools and set up some functions and constants.

```python
from pwn import *

MAZE_SIZE = 20
CELL_SIZE = 0x10

e = ELF("./tunnel", checksec=False)
def read_cell(addr):
    data = e.read(addr, CELL_SIZE)
    return struct.unpack("IIII", data)

def read_coord(coord):
    x, y, z = coord
    addr = e.sym["maze"] + (x * MAZE_SIZE * MAZE_SIZE * CELL_SIZE) + (y * MAZE_SIZE * CELL_SIZE) + (z * CELL_SIZE)
    return read_cell(addr)

START = 0
OPEN = 1
CLOSED = 2
FINISH = 3
```

We'll also add a function to find all adjacent (and in-bounds coordinates).

```python
def get_adj(pos):
    x, y, z = pos
    options = []
    if not x - 1 < 0: options.append((x-1, y, z))
    if not x + 1 >= MAZE_SIZE: options.append((x+1, y, z))
    if not y - 1 < 0: options.append((x, y-1, z))
    if not y + 1 >= MAZE_SIZE: options.append((x, y+1, z))
    if not z - 1 < 0: options.append((x, y, z-1))
    if not z + 1 >= MAZE_SIZE: options.append((x, y, z+1))
    return options
```

We'll set up a `solve` function that records the current path. We will check each adjacent cell and move into it (not visiting the same cell twice).

```python
def solve():
    pos = (0, 0, 0)
    visited = []
    while True:
        for adj in get_adj(pos):
            if adj in visited: continue
            _, _, _, typ = read_coord(adj)
            if typ == OPEN:
                visited.append(pos)
                pos = adj
                break
            elif typ == FINISH:
                return visited + [pos, adj]
        else:
            print(f"failed at {pos}")
```

Finally, we'll turn our solved path into a series of directions and send it to the server.

```python

path = solve()
solution = ""
for i in range(1, len(path)):
    prev = path[i-1]
    cur = path[i]
    if cur[0] > prev[0]:
        solution += "R"
    elif cur[0] < prev[0]:
        solution += "L"
    elif cur[1] > prev[1]:
        solution += "F"
    elif cur[1] < prev[1]:
        solution += "B"
    elif cur[2] > prev[2]:
        solution += "U"
    elif cur[2] < prev[2]:
        solution += "D"
print(solution)
r = remote(args.HOST, args.PORT)
for c in solution:
    r.sendlineafter(b"? ", c.encode())
print(r.recvlines(2)[1].decode())
```
