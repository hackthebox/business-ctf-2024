from sol import *

grid = format_grid('9 3', '8 3 4 20 6 4 15 2 6 13 18 19 5 13 19 4 11 1 6 17 10 1 13 19 9 7 3')
t = find_min_path_sum(grid)

print(t)
