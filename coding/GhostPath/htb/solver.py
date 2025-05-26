#!/usr/bin/env python3
import sys
from collections import deque
sys.setrecursionlimit(1 << 25)

LOG = 20  # ceil(log2(1_000_000)) is ~20

def in_bounds(x, y, N, M): return 0 <= x < N and 0 <= y < M

def get_start_end_coords(data):
  coords = []
  for d in data:
    x1, y1, x2, y2 = map(int, d.split())
    coords.append(((x1 - 1, y1 - 1), (x2 - 1, y2 - 1)))
  return coords

def bfs_tag(_map, grid, N, M):
  ID = 1
  for r in range(N):
    for c in range(M):
      if grid[r][c] == -1:
        terrain = _map[r][c]
        queue = deque([(r, c)])
        while queue:
          x, y = queue.popleft()
          if grid[x][y] != -1: continue
          grid[x][y] = ID
          for dx, dy in [(-1,0), (1,0), (0,-1), (0,1), (-1,-1), (1,1), (-1,1), (1,-1)]:
            nx, ny = x + dx, y + dy
            if in_bounds(nx, ny, N, M) and _map[nx][ny] == terrain and grid[nx][ny] == -1:
              queue.append((nx, ny))
        ID += 1
  return grid, ID - 1

def build_tree(_map, grid, N, M, maxID):
  parent = [0] * (maxID + 1)
  depth = [0] * (maxID + 1)
  up = [[0] * (maxID + 1) for _ in range(LOG)]
  adj = [[] for _ in range(maxID + 1)]
  visited_edges = set()

  for r in range(N):
    for c in range(M):
      curr_id = grid[r][c]
      for dx, dy in [(0, 1), (1, 0), (1, 1)]:
        nx, ny = r + dx, c + dy
        if in_bounds(nx, ny, N, M):
          next_id = grid[nx][ny]
          if curr_id != next_id:
            edge = tuple(sorted((curr_id, next_id)))
            if edge not in visited_edges:
              adj[curr_id].append(next_id)
              adj[next_id].append(curr_id)
              visited_edges.add(edge)

  # BFS to fill parent and depth
  queue = deque([1])
  visited = [False] * (maxID + 1)
  visited[1] = True
  while queue:
    u = queue.popleft()
    for v in adj[u]:
      if not visited[v]:
        parent[v] = u
        depth[v] = depth[u] + 1
        visited[v] = True
        queue.append(v)

  # Binary lifting preprocessing
  for v in range(1, maxID + 1):
    up[0][v] = parent[v]
  for k in range(1, LOG):
    for v in range(1, maxID + 1):
      up[k][v] = up[k-1][up[k-1][v]]

  return depth, up

def lca(u, v, depth, up):
  if depth[u] < depth[v]: u, v = v, u
  for k in reversed(range(LOG)):
    if depth[u] - (1 << k) >= depth[v]:
        u = up[k][u]
  if u == v: return u
  for k in reversed(range(LOG)):
    if up[k][u] != up[k][v]:
      u = up[k][u]
      v = up[k][v]
  return up[0][u]

def solve():
  data = sys.stdin
  N, M = map(int, data.readline().split())
  _map = [list(data.readline().strip()) for _ in range(N)]
  Q = int(data.readline().strip())
  coords = [data.readline().strip() for _ in range(Q)]
  start_end_coords = get_start_end_coords(coords)

  grid = [[-1] * M for _ in range(N)]
  grid, maxID = bfs_tag(_map, grid, N, M)
  depth, up = build_tree(_map, grid, N, M, maxID)

  output = []
  for (sx, sy), (ex, ey) in start_end_coords:
    id1 = grid[sx][sy]
    id2 = grid[ex][ey]
    ancestor = lca(id1, id2, depth, up)
    dist = (depth[id1] + depth[id2] - 2 * depth[ancestor]) // 2
    output.append(str(dist))

  print("\n".join(output))

solve()