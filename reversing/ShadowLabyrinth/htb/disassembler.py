from sage.all import *
from sage.modules.free_module_integer import IntegerLattice

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from pwn import xor
from zlib import decompress
import struct

def read_u32(binary, offset):
    return struct.unpack('<I', binary[offset:offset+4])[0]

def disassemble(binary):
    instructions = []
    offset = 0
    
    while offset < len(binary):
        try:
            opcode = read_u32(binary, offset)
            offset += 4
            
            instruction = {
                'offset': offset - 4,
                'opcode': opcode,
                'args': [],
                'mnemonic': '',
                'text': ''
            }
            
            if opcode == 0:  # reset0
                reg = read_u32(binary, offset)
                offset += 4
                instruction['args'] = [reg]
                instruction['mnemonic'] = 'reset0'
                instruction['text'] = f"reset0 r{reg}"
                
            elif opcode == 1:  # reset1
                reg = read_u32(binary, offset)
                offset += 4
                instruction['args'] = [reg]
                instruction['mnemonic'] = 'reset1'
                instruction['text'] = f"reset1 r{reg}"
                
            elif opcode == 2:  # addi
                reg = read_u32(binary, offset)
                offset += 4
                val = read_u32(binary, offset)
                offset += 4
                instruction['args'] = [reg, val]
                instruction['mnemonic'] = 'addi'
                instruction['text'] = f"addi r{reg}, {val}"
                
            elif opcode == 3:  # subbi
                reg = read_u32(binary, offset)
                offset += 4
                val = read_u32(binary, offset)
                offset += 4
                instruction['args'] = [reg, val]
                instruction['mnemonic'] = 'subbi'
                instruction['text'] = f"subbi r{reg}, {val}"
                
            elif opcode == 4:  # lsli
                reg = read_u32(binary, offset)
                offset += 4
                val = read_u32(binary, offset)
                offset += 4
                instruction['args'] = [reg, val]
                instruction['mnemonic'] = 'lsli'
                instruction['text'] = f"lsli r{reg}, {val}"
                
            elif opcode == 5:  # add
                dst = read_u32(binary, offset)
                offset += 4
                src = read_u32(binary, offset)
                offset += 4
                instruction['args'] = [dst, src]
                instruction['mnemonic'] = 'add'
                instruction['text'] = f"add r{dst}, r{src}"
                
            elif opcode == 6:  # sub
                dst = read_u32(binary, offset)
                offset += 4
                src = read_u32(binary, offset)
                offset += 4
                instruction['args'] = [dst, src]
                instruction['mnemonic'] = 'sub'
                instruction['text'] = f"sub r{dst}, r{src}"
                
            elif opcode == 7:  # xor
                dst = read_u32(binary, offset)
                offset += 4
                src = read_u32(binary, offset)
                offset += 4
                instruction['args'] = [dst, src]
                instruction['mnemonic'] = 'xor'
                instruction['text'] = f"xor r{dst}, r{src}"
                
            elif opcode == 8:  # str
                reg = read_u32(binary, offset)
                offset += 4
                disp = struct.unpack('<i', binary[offset:offset+4])[0]*4  # signed int32
                offset += 4
                instruction['args'] = [reg, disp]
                instruction['mnemonic'] = 'str'
                instruction['text'] = f"str r{reg}, [{(offset + disp):08x}]"
                
            elif opcode == 9:  # ldr
                reg = read_u32(binary, offset)
                offset += 4
                disp = struct.unpack('<i', binary[offset:offset+4])[0]*4  # signed int32
                offset += 4
                instruction['args'] = [reg, disp]
                instruction['mnemonic'] = 'ldr'
                instruction['text'] = f"ldr r{reg}, [{(offset + disp):08x}]"
                
            elif opcode == 10:  # jz
                target = struct.unpack('<i', binary[offset:offset+4])[0]  # signed int32
                offset += 4
                instruction['args'] = [target]
                instruction['mnemonic'] = 'jz'
                abs_target = (offset - 8) + target*4 

                instruction['text'] = f"jz {target:+d} [-> 0x{abs_target:08x}]"
                
            elif opcode == 11:  # jnz
                target = struct.unpack('<i', binary[offset:offset+4])[0]  # signed int32
                offset += 4
                instruction['args'] = [target]
                instruction['mnemonic'] = 'jnz'
                abs_target = (offset - 8) + target*4
                instruction['text'] = f"jnz {target:+d} [-> 0x{abs_target:08x}]"
                
            elif opcode == 12:  # jmp
                target = struct.unpack('<i', binary[offset:offset+4])[0]  # signed int32
                offset += 4
                instruction['args'] = [target]
                instruction['mnemonic'] = 'jmp'
                abs_target = (offset - 8) + target*4
                instruction['text'] = f"jmp {target:+d} [-> 0x{abs_target:08x}]"
                
            elif opcode == 13:  # getch
                instruction['mnemonic'] = 'getch'
                instruction['text'] = "getch"
                
            elif opcode == 14:  # puts
                disp = struct.unpack('<i', binary[offset:offset+4])[0] + 2  # signed int32
                offset += 4
                instruction['args'] = [disp]
                instruction['mnemonic'] = 'puts'
                instruction['text'] = f"puts [{disp:+d}]"
                
                # Try to extract the string being printed if possible
                str_offset = offset + (disp - 2)*4
                if 0 <= str_offset < len(binary):
                    # Read until null terminator
                    string_data = []
                    while str_offset < len(binary):
                        char_val = read_u32(binary, str_offset)
                        if char_val == 0:
                            break
                        string_data.append(chr(char_val))
                        str_offset += 4
                    if string_data:
                        instruction['text'] += f" ; \"{''.join(string_data)}\""
                
            elif opcode == 15:  # exit
                instruction['mnemonic'] = 'exit'
                instruction['text'] = "exit"
                
            else:
                instruction['mnemonic'] = f"unknown_{opcode}"
                instruction['text'] = f"unknown_{opcode}"
            
            instructions.append(instruction)
            
        except Exception as e:
            # If we encounter an error, just show what we have
            print(f"Error at offset 0x{offset:08x}: {e}")
            break
    
    return instructions

def print_disassembly(instructions):
    for insn in instructions:
        print(f"0x{insn['offset']:08x}: {insn['text']}")

# Directly taken from rbtree's LLL repository
# From https://web.archive.org/web/20211006060014/https://oddcoder.com/LOL-34c3/, https://hackmd.io/@hakatashi/B1OM7HFVI
def Babai_CVP(mat, target):
	M = IntegerLattice(mat, lll_reduce=True).reduced_basis
	G = M.gram_schmidt()[0]
	diff = target
	for i in reversed(range(G.nrows())):
		diff -=  M[i] * ((diff * G[i]) / (G[i] * G[i])).round()
	return target - diff


def solve(M, lbounds, ubounds, weight = None):
	mat, lb, ub = copy(M), copy(lbounds), copy(ubounds)
	num_var  = mat.nrows()
	num_ineq = mat.ncols()

	max_element = 0 
	for i in range(num_var):
		for j in range(num_ineq):
			max_element = max(max_element, abs(mat[i, j]))

	if weight == None:
		weight = num_ineq * max_element

    # sanity checker
	if len(lb) != num_ineq:
		print("Fail: len(lb) != num_ineq")
		return

	if len(ub) != num_ineq:
		print("Fail: len(ub) != num_ineq")
		return

	for i in range(num_ineq):
		if lb[i] > ub[i]:
			print("Fail: lb[i] > ub[i] at index", i)
			return

    	# heuristic for number of solutions
	DET = 0

	if num_var == num_ineq:
		DET = abs(mat.det())
		num_sol = 1
		for i in range(num_ineq):
			num_sol *= (ub[i] - lb[i])
		if DET == 0:
			print("Zero Determinant")
		else:
			num_sol //= DET
			# + 1 added in for the sake of not making it zero...
			print("Expected Number of Solutions : ", num_sol + 1)

	# scaling process begins
	max_diff = max([ub[i] - lb[i] for i in range(num_ineq)])
	applied_weights = []

	for i in range(num_ineq):
		ineq_weight = weight if lb[i] == ub[i] else max_diff // (ub[i] - lb[i])
		applied_weights.append(ineq_weight)
		for j in range(num_var):
			mat[j, i] *= ineq_weight
		lb[i] *= ineq_weight
		ub[i] *= ineq_weight

	# Solve CVP
	target = vector([(lb[i] + ub[i]) // 2 for i in range(num_ineq)])
	result = Babai_CVP(mat, target)

	for i in range(num_ineq):
		if (lb[i] <= result[i] <= ub[i]) == False:
			print("Fail : inequality does not hold after solving")
			break
    
    	# recover x
	fin = None

	if DET != 0:
		mat = mat.transpose()
		fin = mat.solve_right(result)
	
	## recover your result
	return result, applied_weights, fin

# The system of equations that we get from the binary that we have to solve.
equation_system = [
    [[14055091775023953042, 4697615361981610810, 13156859446556206221, 9827634565473418386], 13300144332188832633],
    [[5373631360438526983, 16942442890343741447, 3664586747082128017, 14567259116776078067], 12888318284105725407],
    [[6785120272971039627, 10789770647799993750, 16439294865311385781, 6508158523694997399], 10558681868314680195],
    [[1802839430078646867, 6286569574160603382, 9334576314108341274, 5975256149793082424], 10627411219216148408],
    [[18081590721992869275, 17876552896028830478, 15004347904193854619, 18171394467572912155], 11773963806847708635],
    [[13312841314732569691, 7778175297513301391, 7381032535666542733, 18260596666252650869], 12288299245347496658],
    [[9058469793968160760, 6202997293771330668, 6877061413170231308, 16628218849096314863], 8108830967362923143],
    [[12108041809488199247, 13192887724755078504, 4916096456553900087, 2484714295426518693], 10267425364822616444],
    [[11810397209173602435, 4233600866858274491, 14160344317519436691, 10746092446191405905], 2055613089520971530],
    [[1248975127725990079, 2001095475832083806, 1369475499596269645, 14130870301470775307], 13187960460901614106],
    [[13499373392351563463, 18083580916977673865, 16647353807052949688, 8126032605205937982], 2573742750309805842],
    [[4219647702921633222, 17990802922386267876, 14587743928823397188, 3689454119161069336], 7702547848331324668]
]


key = b""
for config in equation_system:
    mat = [
        [config[0][0], 1, 0, 0, 0],
        [config[0][1], 0, 1, 0, 0],
        [config[0][2], 0, 0, 1, 0],
        [config[0][3], 0, 0, 0, 1],
        [2**64, 0, 0, 0, 0]
    ]
    L = [config[1], 0, 0, 0, 0]
    U = [config[1], 256, 256, 256, 256]
    mat = Matrix(mat)
    _,_,res=solve(mat,L,U)
    key += bytes(res[:4])

key2 = bytes(list(key))

with open("./file.bin", "rb") as f:
    dat = f.read()


dat = xor(dat, key2[32:])



iv = [0x8c, 0xa2, 0xca, 0xb2, 0x29, 0xdb, 0x61, 0x0a, 0xac, 0xdd, 0x9d, 0x43, 0x7c, 0x61, 0x7a, 0xf3]
cipher = AES.new(key2[:32], AES.MODE_CBC, bytes(iv))

get_vm_data = unpad(cipher.decrypt(dat), AES.block_size)

get_vm_data = decompress(get_vm_data)

insns = disassemble(get_vm_data)

# get the disassembly
print_disassembly(insns)

# get the binary
with open("./vm_inst", "wb") as f:
    f.write(get_vm_data)
