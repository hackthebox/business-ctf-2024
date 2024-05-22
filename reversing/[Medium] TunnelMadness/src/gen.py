#!/usr/bin/env python3

import math
import random

MAZE_SIZE = 20

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

def dist(a, b):
    ax, ay, az = a
    bx, by, bz = b
    return math.sqrt((bx - ax) ** 2 + (by - ay) ** 2 + (bz - az) ** 2)

def make_maze(pos, dest):
    def try_path(current, next_point):
        new_path = current + [next_point]
        curdist = dist(next_point, dest)
        options = [p for p in get_adj(next_point) if p not in new_path and dist(p, dest) <= curdist + 0.1]
        random.shuffle(options)
        for option in options:
            if option == dest:
                return new_path + [option]
            res = try_path(new_path, option)
            if res:
                return res
        return None
    return try_path([], pos)

start = (0, 0, 0)
end = (MAZE_SIZE-1, MAZE_SIZE-1, MAZE_SIZE-1)
path = make_maze(start, end)

# # Uncomment to render path
# import numpy as np
# import matplotlib.pyplot as plt
# from mpl_toolkits.mplot3d import Axes3D

# # Sample list of points (replace this with your own)
# points = np.array(path)

# # Extract x, y, z coordinates from points
# x = points[:, 0]
# y = points[:, 1]
# z = points[:, 2]

# # Plotting
# fig = plt.figure()
# ax = fig.add_subplot(111, projection='3d')

# # Plot points
# ax.scatter(x, y, z, color='r')

# # Connect points to form a path
# ax.plot(x, y, z, color='b')

# # Set labels and title
# ax.set_xlabel('X')
# ax.set_ylabel('Y')
# ax.set_zlabel('Z')
# ax.set_title('3D Path')

# plt.show()

header = """\
#define MAZE_SIZE %d
struct coord {
    unsigned int x;
    unsigned int y;
    unsigned int z;
};
enum celltype {
    START,
    OPEN,
    CLOSED,
    FINISH,
};
struct cell {
    struct coord pos;
    enum celltype cell_type;
};
""" % (MAZE_SIZE)

with open('maze.h', 'w') as f:
    f.write(header)

maze_inc = f"const struct cell maze[{MAZE_SIZE}][{MAZE_SIZE}][{MAZE_SIZE}] = " + '{\n'
for x in range(MAZE_SIZE):
    maze_inc += '  {\n'
    for y in range(MAZE_SIZE):
        maze_inc += '    {\n'
        for z in range(MAZE_SIZE):
            maze_inc += '      {' + f"{x}, {y}, {z}, "
            coord = (x, y, z)
            if coord == start:
                maze_inc += 'START'
            elif coord == end:
                maze_inc += 'FINISH'
            elif coord in path:
                maze_inc += 'OPEN'
            else:
                maze_inc += 'CLOSED'
            maze_inc += '},\n'
        maze_inc += '    },\n'
    maze_inc += '  },\n'
maze_inc += '};'

with open('maze.inc', 'w') as f:
    f.write(maze_inc)

# solution = ""
# for i in range(1, len(path)):
#     prev = path[i-1]
#     cur = path[i]
#     if cur[0] > prev[0]:
#         solution += "R"
#     elif cur[0] < prev[0]:
#         solution += "L"
#     elif cur[1] > prev[1]:
#         solution += "F"
#     elif cur[1] < prev[1]:
#         solution += "B"
#     elif cur[2] > prev[2]:
#         solution += "U"
#     elif cur[2] < prev[2]:
#         solution += "D"

# print(solution)