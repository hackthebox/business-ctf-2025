#include <iostream>
#include <vector>
#include <unordered_map>
#include <stack>
#include <sstream>
#include <cstdlib>
#include <ctime>
#include <thread>
#include <chrono>
#include <string>

int main() {
    int n;
    std::cin >> n;
    std::cin.ignore(); // consume newline

    std::unordered_map<int, std::vector<int>> tree;

    // Read "a - b" formatted edges
    for (int i = 0; i < n - 1; ++i) {
        std::string line;
        std::getline(std::cin, line);
        std::stringstream ss(line);
        int a, b;
        char dash;
        ss >> a >> dash >> b;
        tree[a].push_back(b);
        tree[b].push_back(a);
    }

    int honeypot;
    std::cin >> honeypot;

    std::vector<int> parent(n + 1, 0);
    std::vector<bool> contains_honeypot(n + 1, false);
    std::vector<int> subtree_size(n + 1, 0);
    std::vector<int> post_order;

    std::stack<int> s;
    s.push(1);
    while (!s.empty()) {
        int node = s.top();
        s.pop();
        post_order.push_back(node);
        for (int neighbor : tree[node]) {
            if (neighbor == parent[node]) continue;
            parent[neighbor] = node;
            s.push(neighbor);
        }
    }

    for (int i = static_cast<int>(post_order.size()) - 1; i >= 0; --i) {
        int node = post_order[i];
        subtree_size[node] = 1;
        contains_honeypot[node] = (node == honeypot);
        for (int neighbor : tree[node]) {
            if (neighbor == parent[node]) continue;
            subtree_size[node] += subtree_size[neighbor];
            contains_honeypot[node] = contains_honeypot[node] || contains_honeypot[neighbor];
        }
    }

    int biggest_subtree = 0;
    for (int node = 1; node <= n; ++node) {
        if (!contains_honeypot[node] && subtree_size[node] > biggest_subtree) {
            biggest_subtree = subtree_size[node];
        }
    }

    std::cout << (n - biggest_subtree) << std::endl;

    return 0;
}
