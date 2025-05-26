#include <iostream>
#include <vector>
#include <queue>
#include <tuple>
#include <algorithm>
#include <set>
#include <string>
#include <cmath>

using namespace std;

const int LOG = 20;
const int dx8[] = {-1, 1, 0, 0, -1, -1, 1, 1};
const int dy8[] = {0, 0, -1, 1, -1, 1, -1, 1};

bool in_bounds(int x, int y, int N, int M) {
    return x >= 0 && x < N && y >= 0 && y < M;
}

void bfs_tag(const vector<string>& grid_map, vector<vector<int>>& grid, int N, int M, int& maxID) {
    int ID = 1;
    for (int r = 0; r < N; ++r) {
        for (int c = 0; c < M; ++c) {
            if (grid[r][c] == -1) {
                char terrain = grid_map[r][c];
                queue<pair<int, int>> q;
                q.push({r, c});
                while (!q.empty()) {
                    auto [x, y] = q.front(); q.pop();
                    if (grid[x][y] != -1) continue;
                    grid[x][y] = ID;
                    for (int d = 0; d < 8; ++d) {
                        int nx = x + dx8[d];
                        int ny = y + dy8[d];
                        if (in_bounds(nx, ny, N, M) && grid_map[nx][ny] == terrain && grid[nx][ny] == -1) {
                            q.push({nx, ny});
                        }
                    }
                }
                ++ID;
            }
        }
    }
    maxID = ID - 1;
}

pair<vector<int>, vector<vector<int>>> build_tree(const vector<vector<int>>& grid, int N, int M, int maxID) {
    vector<vector<int>> adj(maxID + 1);
    set<pair<int, int>> visited_edges;

    for (int r = 0; r < N; ++r) {
        for (int c = 0; c < M; ++c) {
            int curr_id = grid[r][c];
            for (auto [dx, dy] : vector<pair<int, int>>{{0, 1}, {1, 0}, {1, 1}}) {
                int nx = r + dx, ny = c + dy;
                if (in_bounds(nx, ny, N, M)) {
                    int next_id = grid[nx][ny];
                    if (curr_id != next_id) {
                        auto edge = minmax(curr_id, next_id);
                        if (!visited_edges.count(edge)) {
                            visited_edges.insert(edge);
                            adj[curr_id].push_back(next_id);
                            adj[next_id].push_back(curr_id);
                        }
                    }
                }
            }
        }
    }

    vector<int> parent(maxID + 1, 0);
    vector<int> depth(maxID + 1, 0);
    vector<vector<int>> up(LOG, vector<int>(maxID + 1, 0));
    vector<bool> visited(maxID + 1, false);

    queue<int> q;
    q.push(1);
    visited[1] = true;
    while (!q.empty()) {
        int u = q.front(); q.pop();
        for (int v : adj[u]) {
            if (!visited[v]) {
                visited[v] = true;
                parent[v] = u;
                depth[v] = depth[u] + 1;
                q.push(v);
            }
        }
    }

    for (int v = 1; v <= maxID; ++v)
        up[0][v] = parent[v];
    for (int k = 1; k < LOG; ++k)
        for (int v = 1; v <= maxID; ++v)
            up[k][v] = up[k-1][up[k-1][v]];

    return {depth, up};
}

int lca(int u, int v, const vector<int>& depth, const vector<vector<int>>& up) {
    if (depth[u] < depth[v]) swap(u, v);
    for (int k = LOG - 1; k >= 0; --k) {
        if (depth[u] - (1 << k) >= depth[v])
            u = up[k][u];
    }
    if (u == v) return u;
    for (int k = LOG - 1; k >= 0; --k) {
        if (up[k][u] != up[k][v]) {
            u = up[k][u];
            v = up[k][v];
        }
    }
    return up[0][u];
}

int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N, M;
    cin >> N >> M;
    vector<string> grid_map(N);
    for (int i = 0; i < N; ++i) {
        cin >> grid_map[i];
    }

    int Q;
    cin >> Q;
    vector<tuple<int, int, int, int>> queries(Q);
    for (int i = 0; i < Q; ++i) {
        int x1, y1, x2, y2;
        cin >> x1 >> y1 >> x2 >> y2;
        queries[i] = {x1 - 1, y1 - 1, x2 - 1, y2 - 1};
    }

    vector<vector<int>> grid(N, vector<int>(M, -1));
    int maxID;
    bfs_tag(grid_map, grid, N, M, maxID);
    auto [depth, up] = build_tree(grid, N, M, maxID);

    for (auto [sx, sy, ex, ey] : queries) {
        int id1 = grid[sx][sy];
        int id2 = grid[ex][ey];
        int ancestor = lca(id1, id2, depth, up);
        int dist = (depth[id1] + depth[id2] - 2 * depth[ancestor]) / 2;
        cout << dist << '\n';
    }

    return 0;
}
