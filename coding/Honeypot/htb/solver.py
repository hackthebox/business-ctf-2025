#!/usr/bin/env python3
from collections import defaultdict, deque

def solve():
  n = int(input())
  # adjencency list instead of Node class - faster
  tree = defaultdict(list)
  for _ in range(n-1):
    p, c = map(int, input().split(" - "))
    tree[p].append(c)
    tree[c].append(p)
  honeypot = int(input().strip())

  parent = [0] * (n + 1)
  contains_honeypot = [False] * (n + 1)
  subtree_size = [0] * (n + 1)

  post_order = []
  stack = deque([1])
  while stack:
    node = stack.pop()
    post_order.append(node)
    for neighbor in tree[node]:
      if neighbor == parent[node]: continue
      parent[neighbor] = node
      stack.append(neighbor)

  for node in reversed(post_order):
    subtree_size[node] = 1
    contains_honeypot[node] = node == honeypot
    for neighbor in tree[node]:
      if neighbor == parent[node]: continue
      subtree_size[node] += subtree_size[neighbor]
      contains_honeypot[node] |= contains_honeypot[neighbor]
  
  biggest_subtree, firewall_node = 0, 0
  for node in range(1, n + 1):
    if subtree_size[node] > biggest_subtree and not contains_honeypot[node]:
      biggest_subtree = subtree_size[node]
      firewall_node = node
  
  print(n - biggest_subtree)

solve()