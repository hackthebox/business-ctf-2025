![](../../assets/banner.png)

<img src="../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align="left" />        <font size="10">Honeypot</font>

​        30<sup>th</sup> April 2025 / Document No. DYY.102.XX

​        Prepared By: 131LL

​        Challenge Author(s): 131LL

​        Difficulty: <font color=green>Easy</font>

​        Classification: Official

# Synopsis

Honeypot is an easy coding challenge that requires players to model a tree structure, traverse it in post-order, and analyze subtrees to make an optimal cut.
The player must identify where to place a firewall while ensuring a honeypot node remains reachable, combining tree traversal, parent tracking, and greedy logic.

## Skills Required

- Basic understanding of trees and graph traversal

## Skills Learned

- Tree traversal using an explicit stack (non-recursive DFS)
- Post-order processing for bottom-up aggregation
- Subtree size computation
- Greedy decision making
- Boolean propagation in hierarchical data

## Description

```
A Volnayan breach has reached deep into your network, with lateral movement already underway.
As Orion “Circuitbreaker” Zhao, you must deploy a firewall to isolate the threat — but the honeypot must remain connected for surveillance.
Choose the cut point carefully: the fewer nodes exposed, the better your containment.
```

## Technical Description

```
Using credentials flagged in the previous investigation, Volnayan APTs have successfully breached a critical internal router.
Telemetry from the affected systems indicates active lateral movement attempts.

As Orion “Circuitbreaker” Zhao, your mission is to contain the breach before it spreads further into critical infrastructure.
You have a single opportunity to deploy a firewall between two network nodes to limit exposure.
However, a honeypot node — strategically placed for surveillance — must remain reachable from the compromised root node.

The objective is to determine the minimum number of nodes that will still be reachable (i.e., exposed) from the root node
after placing the firewall optimally, while ensuring the honeypot remains connected.

The input has the following format:

The first line contains an integer N.
The network is a tree with N nodes and N-1 connections.
The next N-1 lines describe the connections of the network, with a format of "A - B", where A and B are integer IDs, representing network nodes.
The last line of the input defines the honeypot's node ID, H.

10 <= N <= 10^6

Example:

7
1 - 2
1 - 3
3 - 4
3 - 5
1 - 6
6 - 7
5

We can construct the following network tree with our input:

   __ 1 ___
 /    |     \
2     3      6
     / \      \
    4   5(H)   7

By placing the firewall between nodes 1 and 3, the nodes 3, 4, and 5 would be cut off from the network, leaving a total of 4 exposed nodes (1, 2, 6, 7).
That is the maximum number of nodes we can cut off with one firewall, but since node 5 is the honeypot and must be left exposed, the firewall cannot be placed between nodes 1 and 3.
Placing the firewall between nodes 1 and 6 which will cut off nodes 6 and 7 from the network.
This leaves us with 5 exposed nodes (1, 2, 3, 4, and 5), which is the minimum number, given the problem restriction of keeping the honeypot node exposed.

So, the correct answer in this example is "5".
```

## Solving the challenge

To start, we will parse our input data and keep track of the network tree using adjacency lists for better performance.

```python
from collections import defaultdict, deque
n = int(input())
# adjancency list instead of a Node class - faster
tree = defaultdict(list)
for _ in range(n-1):
  p, c = map(int, input().split(" - "))
  tree[p].append(c)
  tree[c].append(p)
honeypot = int(input().strip())

# lookup lists
parent = [0] * (n + 1) # each node has one parent - except root which has 0
contains_honeypot = [False] * (n + 1)
subtree_size = [0] * (n + 1)
```

Next, we perform a non-recursive DFS traversal using a stack. We keep track of each node's parent node to prevent revisiting. This way, we build a post-order traversal list for bottom-up processing.

```python
post_order = []
stack = deque([1])
while stack:
  node = stack.pop()
  post_order.append(node)
  for neighbor in tree[node]:
    if neighbor == parent[node]: continue
    parent[neighbor] = node
    stack.append(neighbor)
```

Now, in reversed post-order, we compute the subtree size rooted in each node, and mark whether the subtree contains the honeypot.
This aggregation is essential to make informed decisions on where to "cut" with the firewall.

```python
for node in reversed(post_order):
  subtree_size[node] = 1
  contains_honeypot[node] = node == honeypot
  for neighbor in tree[node]:
    if neighbor == parent[node]: continue
    subtree_size[node] += subtree_size[neighbor]
    contains_honeypot[node] |= contains_honeypot[neighbor]
```

Finally, we will apply a greedy strategy to evaulate possible cuts through the firewall placement. We will be scanning all nodes to find the largest subtree that does not contain the honeypot. This subtree is considered the best candidate for isolation via the firewall. The output can be calculated easily, subtracting the size of the largest subtree (that doesn't contain the honeypot) from the total number of nodes.

```python
biggest_subtree = 0
for node in range(1, n + 1):
  if subtree_size[node] > biggest_subtree and not contains_honeypot[node]:
    biggest_subtree = subtree_size[node]

print(n - biggest_subtree)
```
