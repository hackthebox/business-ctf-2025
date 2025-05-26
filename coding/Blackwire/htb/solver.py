import sys

def solve():
  T, L = map(int, input().strip().split(' '))
  transitions = [0x00] * T
  for _ in range(T):
    state, opcode = int(sys.stdin.read(12), 2), int(sys.stdin.read(8), 2)
    transitions[state] = opcode

  opcode_exec_stream = []
  for i in range(0, L, 8):
    opcode_exec_stream.append(int(sys.stdin.read(8), 2))
  
  m = L // 8

  dp_table = [[0] * (T + 1) for _ in range(m + 1)]
  for i in range(m + 1):
    dp_table[i][0] = 1
  
  for i in range(1, m + 1):
    for j in range(1, T + 1):
      if opcode_exec_stream[i - 1] == transitions[j - 1]:
        dp_table[i][j] = dp_table[i - 1][j - 1] + dp_table[i - 1][j]
      else:
        dp_table[i][j] = dp_table[i - 1][j]
  
  print(dp_table[m][T])
  

solve()