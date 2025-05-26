from z3 import *
from pwn import xor

x = [Int(f'x{i}') for i in range(10)]

s = Solver()
levels = [6, 5, 4]

constraints = [
    [x[0] > x[2], x[1] < x[4], x[2] > x[5], x[3] > x[4], x[5] > x[3]],
    [x[0] > x[4], x[1] < x[4], x[2] < x[3], x[3] < x[1]],
    [x[0] > x[1], x[2] < x[1], x[2] > x[3]]
]

ans = ''

for i in range(len(levels)):
    s.push()

    for j in range(levels[i]-1):
        s.add(constraints[i][j])

    s.add(And([And(x[ii] >= 0, x[ii] < levels[i]) for ii in range(10)]))
    s.add(Distinct(x[:levels[i]]))

    for v in x[levels[i]:]:
        s.add(v == 0)

    if s.check() == sat:
        m = s.model()
        ans += ''.join([str(m.evaluate(x[ii])) for ii in range(10) if ii < levels[i]])

    s.pop()
    

print(xor(b'}dvIA_\x00FV\x01A^\x01CoG\x03BD\x00]SO', ans.encode()))
