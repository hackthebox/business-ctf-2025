![](../../assets/banner.png)

<img src="../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align="left" />        <font size="10">Ghost Path</font>

​        30<sup>th</sup> April 2025 / Document No. DYY.102.XX

​        Prepared By: 131LL

​        Challenge Author(s): 131LL

​        Difficulty: <font color=red>Hard</font>

​        Classification: Official

# Synopsis

Ghost Path is a hard coding challenge. It is set in a surveillance-heavy combat zone, where players must determine the safest route between two points in a grid where cells are either safe or drone-controlled. The twist: the grid is grouped into connected terrain zones, and movement between these zones forms a virtual tree. Players must efficiently compute the number of drone-controlled regions crossed for up to 150,000 queries — a task that demands strong grasp of tree structures, BFS tagging, and Lowest Common Ancestor (LCA) techniques.

## Skills Required

- Solid understanding of 2D grids and connected component labeling
- Familiarity with BFS (Breadth-First Search)
- Basic graph construction and traversal
- Understanding of tree depth, parent-child relationships
- Knowledge of binary lifting for fast LCA queries

## Skills Learned

- Implementing BFS to label connected regions in a 2D grid
- Building a region-adjacency graph from a grid map
- Converting a grid problem into a tree problem for efficient querying
- Preprocessing a tree with binary lifting for `O(log N)` LCA queries
- Applying depth and parent tracking to compute distances in a tree
- Handling large-scale query input with optimized data structures

## Description

```
A hidden uplink powering Volnayan drone networks has been located deep in hostile terrain.
Your team must navigate the grid to reach and disable it — but every step into a drone-patrolled zone increases the risk of detection.
Chart the safest route through the surveillance field, and minimize exposure before the next wave is unleashed.
```

## Technical Description

```
Following the takedown of the logic bomb payload, Task Force Phoenix has uncovered the location of a hidden Volnayan signal relay —
an uplink believed to coordinate autonomous drone patrols and transmit activation sequences to compromised infrastructure nodes.

Your team must advance through hostile terrain to reach and disable this node before the next wave of Operation Blackout can be executed.
Recon sweeps led by Nava “Sleuth” Patel have flagged suspected drone surveillance zones, while Sable “Overwatch” Kimura has mapped viable routes.
Orion “Circuitbreaker” Zhao has verified the signal emitter’s structural vulnerability, and Talion “Little Byte” Reyes is monitoring electromagnetic signatures for signs of decoy nodes.

The terrain is presented as a grid. Safe zones are marked with ".", while suspected drone-patrolled zones are marked with "X".
Your team may move in any of the 8 directions — up, down, left, right, or diagonally — as long as they stay within grid bounds.

Each time your team steps into a suspected drone zone ("X"), it counts as a risk exposure, regardless of duration.
Your goal is to determine the safest possible path — the one that minimizes the number of drone zones entered en route to the uplink.

Both the starting position and the signal node are guaranteed to be in safe zones (".").

The input has the following format:

The first line contains two integers, N and M.  
N is the number of rows in the grid, and M is the number of columns.  
The next N lines each contain M characters — the terrain map.  
The following line contains an integer Q, the number of queries.  
The next Q lines give the player a starting position row1 col1 and an uplink position row2 col2 (1-indexed).

The goal is to calculate the minimum number of drone-controlled areas the team has to step into for each query.

10 <= N, M <= 1000
1 <= Q <= 75000

Example:

5 12
...XX..XXXXX
XX.XX.XX...X
XX.XX..X.X.X
XXXXXX.XXXXX
X...XX.XXXXX
3
1 1 2 11 
5 3 3 3
1 1 3 3

Expected Output:
2
1
0
```

## Solving the challenge

Input parsing and preparation is the first step in any coding challenge.

```python
data = sys.stdin
N, M = map(int, data.readline().split())
_map = [list(data.readline().strip()) for _ in range(N)]
Q = int(data.readline().strip())
coords = [data.readline().strip() for _ in range(Q)]
```

* `N x M` grid of cells is read, where each cell is either `safe` or a `drone zone`
* `Q` queries follow, each specifying two points on the grid (start and end)
* All coordinates are 1-indexed and are later converted to 0-indexed

Next, we will be using a helper function to organize the query data:

```python
start_end_coords = get_start_end_coords(coords)
```

The helper function itself:

```python
def get_start_end_coords(data):
  coords = []
  for d in data:
    x1, y1, x2, y2 = map(int, d.split())
    coords.append(((x1 - 1, y1 - 1), (x2 - 1, y2 - 1)))
  return coords
```

Next up, we will perform BFS tagging to organize connected cells into regions with a given ID.

Since this is not a traditional pathfinding challenge, and the objective is to determine the minimum number of drone-controlled zones we have to traverse, we want to eventually simplify the grid into a graph or tree, where each node is a separate region on the grid.

```python
grid = [[-1] * M for _ in range(N)]
# grid, unlike the _map, contains region IDs
# maxID is the largest ID given to a region
grid, maxID = bfs_tag(_map, grid, N, M)
```

```python
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
          # all 8 directions
          for dx, dy in [(-1,0), (1,0), (0,-1), (0,1), (-1,-1), (1,1), (-1,1), (1,-1)]:
            nx, ny = x + dx, y + dy
            if in_bounds(nx, ny, N, M) and _map[nx][ny] == terrain and grid[nx][ny] == -1:
              queue.append((nx, ny))
        ID += 1
  return grid, ID - 1
```

If we look at the data carefully, we realize that connecting the regions forms a tree, and not a general graph.

Let's build the tree with our organized data:

```python
depth, up = build_tree(_map, grid, N, M, maxID)
```

The `build_tree` function returns 2 variables:
1. `depth[v]`
* The depth of region `v` in the tree (distance from root)
* Used to compute distances and determine LCA
2. `up[k][v]`
* A binary tree lifting table where `up[k][v] = 2^k-th` ancestor of node `v`
* Used to answer LCA queries in `O(log N)` time

```python
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
```

There is a lot to unpack here. Let's walk through some key points.

Let's explain the use of some variables:
* `parent[v]`: parent of region `v` in the tree
* `adj[v]`: adjacency list for the region graph
* `visited_edges`: avoids adding duplicate edges between regions

Then the next part:

```python
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
```

* Walks through each cell and checks only right, down, and diagonal-down-right to avoid double counting
* If the neighboring cells belong to a different region, we add an edge between these two region IDs
* `visited_edges` ensures we only add each edge once, since the graph is undirected

At this point, we have a full adjacency list of which regions are neighbors, regardless of terrain type.

Next is the BFS tree construction:

```python
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
```

* This builds a BFS tree rooted at region `1`
* It fills in `parent[v]` and `depth[v]`

This establishes a tree structure among the regions for use with binary lifting

Binary lifting is now applied to efficiently compute ancestors at powers of 2, enabling LCA queries in logarithmic time.
* `up[0][v]` = parent of `v`
* `up[1][v]` = parent of parent (2 steps up)
* `up[2][v]` = ... (4 steps up)
* `...`

By combining powers of 2, you can jump up any height in O(log N) time. This is essential for fast Lowest Common Ancestor (LCA) queries, which are used to compute path lengths between regions.

Now that we understand the workings of the `build_tree` function, let's move on to the final piece of the puzzle; the Lowest Common Ancestor (LCA) algorithm.

```python
sys.setrecursionlimit(1 << 25)
LOG = 20  # ceil(log2(1_000_000)) is ~20

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
```

First, the `lca` function ensures `u` is the deeper node (if not, it swaps `u` and `v`). This simplifies the logic; we'll lift u upward until it's at the same depth as `v`.

The first loop uses binary lifting to move `u` up to the same depth as `v`, jumping in powers of 2.

The purpose of the second loop is finding the divergence point. Now that `u` and `v` are at the same depth, we lift them up together until their ancestors match. Finally, we return their lowest shared ancestor.

With everything we have implemented, we can quickly answer all queries the problem throws at us. The answer to each query can easily be calculated with this formula:

`answer = (depth[ID1] + depth[ID2] - 2 * depth[ANCESTOR]) // 2`

We are dividing by 2, since we are passing a drone controlled zone on every other step, and we know the start / end positions are always safe zones.

```python
  output = []
  for (sx, sy), (ex, ey) in start_end_coords:
    id1 = grid[sx][sy]
    id2 = grid[ex][ey]
    ancestor = lca(id1, id2, depth, up)
    dist = (depth[id1] + depth[id2] - 2 * depth[ancestor]) // 2
    output.append(str(dist))

  print("\n".join(output))
```

This approach ensures all queries are answered in `O(log N)` time after `O(N × M)` preprocessing, making the solution scalable even for large grids and heavy query loads.
