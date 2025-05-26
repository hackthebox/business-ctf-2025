import gdb
import os

print("FIXME(clubby): `0x7fffffbfd320` won't work for everyone, need to produce it dynamically")

# dispatcher breakpoint
gdb.execute("break *(0x18d0 + 0x000555555554000)")

rax_values = []

count = 0
count_steps = 0
reg = 0
regs = []
mat = []

def breakpoint_handler(event):
    global count, count_steps, rax_values, regs
    addr = gdb.execute("print/x $rip", to_string=True).split()[-1]
    addr = int(addr, 16) - 0x000555555554000

    if addr == 0x18d0:
        if count_steps == 0:
            gdb.execute("disable break 1")
            gdb.execute(f"rwatch *((0x7bf00 + {reg * 4}) + 0x7fffffbfd320)")
        elif count_steps > 0:
            if ((count_steps) % 3) == 0:
                gdb.execute("disable break 1")
                gdb.execute(f"enable break {reg + 2}")
                r36 = int(gdb.execute("print/x *(unsigned int *)(0x7fffffbfd320 + 0x400000 + (36 * 4))", to_string=True).split()[-1], 16)
                regs += [r36]
        count_steps += 1
    else:
        gdb.execute(f"disable break {reg + 2}")
        gdb.execute("enable break 1")
        count += 1

    print(regs)

gdb.events.stop.connect(breakpoint_handler)

ct = 0
while reg < 35:
    if not os.path.exists('flag.txt'):
        with open('flag.txt', 'w') as f: f.write("HTB{" + ("A"*83) + "}")
    gdb.execute("r < ./flag.txt")
    while True:
        try:
            # fixed number (we can get it by incrementing until the try fails)
            if ct == 4934:
                break

            gdb.execute("continue")
            ct += 1
        except:
            break
    mat += [regs]
    gdb.execute(f"delete break {reg + 2}")
    gdb.execute(f"enable break 1")
    count = 0
    count_steps = 0
    regs = []
    reg += 1

mat = [tuple(col) for col in zip(*mat)]
print(mat)

ans = tuple()

# now dump the answer vector that was generated as well at 0x7bde8
for i in range(35):
    ans += (int(gdb.execute(f"print/x *(unsigned int *)(0x7fffffbfd320 + 0x7bde8 + {i *4})", to_string=True).split()[-1], 16),)

print(ans)


