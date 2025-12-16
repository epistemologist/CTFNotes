# NiteCTF 2025

## Cryptogtaphy - Stronk Rabin
Exploit of implementation of Rabin cryptosystem:
```python3
from pwn import *
import re, json
from sympy import primerange
from itertools import product
from tqdm import tqdm
from Crypto.Util.number import long_to_bytes

r = remote("stronk.chals.nitectf25.live", 1337, ssl=True)
# Receive encrypted flag value
_ = r.recvline()
C = json.loads(r.recvline())['C']
# Leak modulus N = p*q*r*s
r.sendline(json.dumps({"func": "ENC", "args": [2**512]}))
leak = json.loads(r.recvline())["retn"]
N = 2**1024 - leak
for p in primerange(10000):
	while N % p == 0: N //= p
# Collect sums of plaintexts
pt_sums = set()
for _ in tqdm(range(5000)):
	r.sendline(json.dumps({"func": "DEC", "args": [C]}))
	pt_sum = json.loads(r.recvline())["retn"]
	pt_sums.add( pt_sum )
# Get flag
out = set()
for s1, s2 in product(pt_sums, pt_sums):
	# For one of these, s1 = r1+r2+...+r8
	# s2 = r1+r2+...+-r8
	# => s1+s2 = 2r1+2r2+...+2r7
	# Divide through by 2 and subtract s1
	# => (s1+s2)/2 - s1 = r7
	if (s1+s2)%2 == 0:
		r = (s1+s2)//2 - s1
		if pow(r, 2, N) == C:
			out.add(r % N)
for i in out:
	if long_to_bytes(i).startswith("nite"):
		print(long_to_bytes(i))
```

## AI - floating-point guardian
Compile source to shared object and use `scipy` to optimize:

```python3
import ctypes
from math import isnan
from scipy.optimize import minimize

# Set up interface to C function
lib = ctypes.CDLL("./libsrc.so")

DoubleArray = ctypes.c_double * 15
lib.forward_pass.argtypes = [DoubleArray]
lib.forward_pass.restype = ctypes.c_double

def forward_pass(inp):
    assert len(inp) == 15
    return lib.forward_pass(DoubleArray(*inp))

GOAL_Y = 0.7331337420
def f(inp):
    y = forward_pass(inp)
    out = abs(y - GOAL_Y)
    return 10000 if isnan(out) else out


x_opt = minimize(f, x0 = [0. for _ in range(15)], method = 'tnc').x

#ncat --ssl floating.chals.nitectf25.live 1337
from pwn import remote

r = remote("floating.chals.nitectf25.live", 1337, ssl = True)
for i in x_opt:
    r.sendline(str(i).encode())
r.interactive()
```