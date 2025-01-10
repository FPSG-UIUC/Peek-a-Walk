import numpy as np
from lwe_with_hints import *
import time
import pdb

"""
    Extended Euclidean Algorithm
"""
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)
    
"""
    Mod-q erase dependent vectors
"""
def modq_erase(M, q):
    rows, cols = M.shape
    rowCtr = 0
    eliminatedCoordinates = 0
    independent_row = []

    while rowCtr < rows:
        colCtr = eliminatedCoordinates
        foundInvertible = False
        while colCtr < cols and not foundInvertible:
            g, s, _ = egcd(M[rowCtr,colCtr], q)
            if g==1:
                foundInvertible = True
            else:
                colCtr += 1
    
        if foundInvertible:
        
            M[:,colCtr] *= s
            M[:,colCtr] %= q
        
            if colCtr != eliminatedCoordinates:
                M[:,[eliminatedCoordinates,colCtr]] = M[:,[colCtr,eliminatedCoordinates]]
        
            for colCtr in range(cols):
                if colCtr != eliminatedCoordinates:
                    M[:,colCtr] -= M[rowCtr,colCtr]*M[:,eliminatedCoordinates]
                    M[:,colCtr] %= q
        
            eliminatedCoordinates += 1
            independent_row.append(rowCtr)
    
        rowCtr += 1
    return independent_row


# parameters
N = 256
q = 8380417
k = 4
l = 4

"""
Extract Hints from the c file
"""
# construct rotation matrix and sign matrix
poly_idx_list = np.linspace(start=0, stop=N-1, num=N, dtype=int)
rotation_matrix = np.zeros((N,N), dtype=int)
sign_matrix = np.zeros((N,N), dtype=int)
for i in range(N):
    for j in range(N):
        c = 1
        if j < i:
            c = -1
        rotation_matrix[i][j] = poly_idx_list[(j-i)%256]
        sign_matrix[i][j] = c

# open c files
with open("src/c.txt", "r") as f_c:
    c_lines = f_c.readlines()
# traverse lines to collect hints
hints = []
values = []
line_idx = 0
while line_idx < len(c_lines):
    c_vec = [int(chara) for chara in c_lines[line_idx].strip().split(' ')]
    assert len(c_vec) == N
    line_idx += 1
    # read ptr_idx and delta
    while line_idx < len(c_lines):
        sample_vec = [int(chara) for chara in c_lines[line_idx].strip().split(' ')]
        if len(sample_vec) != 2:
            break
        ptr_idx, delta = sample_vec
        hint = [sign*c_vec[idx]%q \
                for sign, idx in zip(sign_matrix[:,(ptr_idx+1)%N], \
                rotation_matrix[:,(ptr_idx+1)%N])]
        hint = [0]*((ptr_idx+1)//256)*256 + hint + [0]*(1024//256 - 1 - (ptr_idx+1)//256)*256
        hints.append(hint)
        values.append(delta)
        line_idx += 1
# filter out the independent rows
independent_row = modq_erase(np.array(hints), q)
print(f"[+] Get {len(independent_row)} independent hints!")
hints = np.array(hints)[independent_row]
values = np.array(values)[independent_row]

"""
Construct target LWE victim
"""
_, invR, _ = egcd(4193792, q)
# load public key A & t
with open("src/pk.txt", "r") as f_pk:
    pk_lines = f_pk.readlines()

A = []
for i in range(l):
    for j in range(k):
        A.append(np.array([int(chara) for chara in pk_lines[j*k+i].strip().split(' ')]) \
                 * invR % q)

t = []
for i in range(k):
    t += [int(chara) for chara in pk_lines[l*k+i].strip().split(' ')]

A = module(A, k, l)
t = np.array(t) % q

# load secret key to double check public key
with open("src/sk.txt", "r") as f_sk:
    sk_lines = f_sk.readlines()
secret_key_flat1 = []
secret_key_flat2 = []
for i in range(l):
    secret_key_flat1 += [int(chara) for chara in sk_lines[i].strip().split(' ')]
for i in range(k):
    secret_key_flat2 += [int(chara) for chara in sk_lines[l+i].strip().split(' ')]
t_computed = (np.array(secret_key_flat1).dot(A) % q + secret_key_flat2) % q
assert np.all(t == t_computed)

# generate lattice
lattice = LWELattice(A, t, q, verbose=True)

"""
Lattice Reduction
"""
# add hint
for idx, hint in enumerate(hints):
    try:
        assert hint.dot(np.array(secret_key_flat1)) % q == values[idx] % q
    except AssertionError:
        pdb.set_trace()
    lattice.integrateModularHint(hint, values[idx] % q, q)

# lattice reduction
start = time.time()
lattice.reduce()
end = time.time()

print(f"[+] Finishing -> Time consumption: {end-start}")
print(lattice.s)
with open("src/guess_sk.txt", 'w') as f_g:
    for i in range(len(lattice.s)):
        f_g.write(f"{lattice.s[i]}\n")

# open secret key file and compare
count = 0
for i in range(len(secret_key_flat1)):
    if int(secret_key_flat1[i]) % q == lattice.s[i] % q:
        count += 1
print(f"Accuracy: {count}/{len(secret_key_flat1)}")
