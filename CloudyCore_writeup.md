# CloudyCore

 ## Challenge info

```text
Level: medium
Category: reverse

Tavsif: Twillie, the memory-minder, was rewinding one of her snowglobes when she overheard a villainous whisper. The scoundrel was boasting about hiding the Starshard's true memory inside this tiny memory core (.tflite). He was so overconfident, laughing that no one would ever think to reverse-engineer a 'boring' ML file. He said he 'left a little challenge for anyone who did,' scrambling the final piece with a simple XOR just for fun. Find the key, reverse the laughably simple XOR, and restore the memory.
```

## Solution

### 1) Extract the zip and read the file

```bash
unzip rev_cloudy_core.zip -d cloudycore
cd cloudycore
ls -la
```

You should see a TensorFlow Lite model, typically:

- `snownet_stronger.tflite`

---

### 2) Identify the file

```bash
file snownet_stronger.tflite
```

This confirms it’s a `.tflite` model (a FlatBuffers container).

A quick skim with `strings` is often enough to tell if anything interesting was embedded:

```bash
strings -n 4 snownet_stronger.tflite | head -n 80
```

---

### 3) What we’re reversing (the “twist”)

A `.tflite` file is a **FlatBuffers** blob that contains (among other things) a list of **Buffers**:
- Real tensors (weights, constants)
- Sometimes metadata / custom blobs

For this challenge, two buffers matter:

1) A **16-byte** blob that decodes like UTF-16LE:
   - Raw bytes look like: `k\x00@\x003\x00@\x00y\x00@\x00!\x00@\x00`
   - Which is the string: `k@3@y@!@`
   - Removing the `@` padding → **key = `k3y!`**

2) A **36-byte** blob that looks random → **ciphertext**

The challenge hint says the final piece is “a simple XOR”, so we XOR the ciphertext with the repeating key `k3y!`.

After XOR, the result starts with `0x78 0x9c`, which is a common **zlib** stream header.
So we zlib-decompress the XOR output → plain text flag.

---

## Solve Script

Save this as `solve.py` in the same folder as `snownet_stronger.tflite`:

```python
#!/usr/bin/env python3
import struct
import zlib

PATH = "snownet_stronger.tflite"

data = open(PATH, "rb").read()

def u32(off): return struct.unpack_from("<I", data, off)[0]
def i32(off): return struct.unpack_from("<i", data, off)[0]
def u16(off): return struct.unpack_from("<H", data, off)[0]

# FlatBuffer root table offset
root = u32(0)

# Model vtable
vt_off = i32(root)
vt = root - vt_off
vlen = u16(vt)
field_offsets = [u16(vt + 4 + 2*i) for i in range((vlen - 4)//2)]

# Find the buffers vector.
# (In this challenge it has length 9; we detect it by scanning root fields.)
buffers_vec = None
for fo in field_offsets:
    if fo == 0:
        continue
    pos = root + fo
    tgt = pos + u32(pos)
    if tgt + 4 <= len(data):
        ln = u32(tgt)
        if ln == 9:
            buffers_vec = tgt
            break

if buffers_vec is None:
    raise RuntimeError("buffers vector topilmadi")

# Extract Buffer.data blobs
blobs = []
ln = u32(buffers_vec)

for i in range(ln):
    ep = buffers_vec + 4 + 4*i
    table = ep + u32(ep)

    # Buffer table vtable
    b_vt_off = i32(table)
    b_vt = table - b_vt_off
    b_vlen = u16(b_vt)

    # Buffer has 1 field: data
    data_field_off = u16(b_vt + 4) if b_vlen >= 6 else 0
    if data_field_off == 0:
        blobs.append(b"")
        continue

    field_pos = table + data_field_off
    vec = field_pos + u32(field_pos)
    blen = u32(vec)
    blob = data[vec + 4 : vec + 4 + blen]
    blobs.append(blob)

# 16-byte UTF-16LE-ish: "k@3@y@!@" -> key = "k3y!"
key_blob = next(b for b in blobs if len(b) == 16 and b and b[1::2] == b"\x00"*8)
key = key_blob[0::2].replace(b"@", b"")  # b'k3y!'

# 36-byte ciphertext
cipher = next(b for b in blobs if len(b) == 36)

# XOR -> zlib -> flag
xored = bytes(cipher[i] ^ key[i % len(key)] for i in range(len(cipher)))
flag = zlib.decompress(xored).decode()

print("key:", key.decode())
print("flag:", flag)
```

Run:

```bash
python3 solve.py
```

---

## Flag

`HTB{Cl0udy_C0r3_R3v3rs3d}`
