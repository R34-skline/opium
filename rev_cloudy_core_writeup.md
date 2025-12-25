# `rev_cloudy_core.zip` — flagni 0dan topish (step-by-step)

Quyidagi yo‘l bilan `rev_cloudy_core.zip` ichidan flag topiladi (Linux/WSL/macOS terminal).

---

## 0) ZIPni ochish

```bash
unzip rev_cloudy_core.zip -d rev_cloudy_core
cd rev_cloudy_core
find . -maxdepth 2 -type f -print
```

Odatda ichidan shunga o‘xshash fayl chiqadi:

- `snownet_stronger.tflite`

---

## 1) Fayl turini tekshirish

```bash
file snownet_stronger.tflite
```

Bu **TensorFlow Lite** model fayli bo‘ladi (`.tflite`).

Tez “hint”lar uchun:

```bash
strings -n 4 snownet_stronger.tflite | head -n 50
```

Ko‘pincha shular ko‘rinadi:

- `TFL3` (TFLite flatbuffer identifikatori)
- `CONVERSION_METADATA`
- `min_runtime_version`
- `in_payload`, `in_meta` (modelga qo‘shilgan nomlar bo‘lishi mumkin)

---

## 2) Reversing mantiqi (g‘oya)

TFLite modeli ichida **Buffers** bo‘limi bo‘ladi — u yerda tensorlar/metadata uchun **raw bytes** saqlanadi.

Bizga kerak bo‘ladigan 3 narsa:

1. **16 baytli** buffer ichidan **UTF-16LE** ko‘rinishda `"k@3@y@!@"` chiqadi  
   → bu **kalit**: `k3y!`

2. **36 baytli** random ko‘rinishdagi buffer  
   → bu **ciphertext**

3. Ciphertext’ni `k3y!` bilan **XOR** qilsak, natijaning boshida `78 9c` chiqadi  
   → bu **zlib** stream belgisi

4. XOR natijasini `zlib` bilan **decompress** qilsak → **flag**

---

## 3) Flagni avtomatik chiqaradigan minimal skript

Quyidagini `solve.py` qilib saqlang:

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

# Model ichidan buffers vektorini topamiz (bu challenge’da u 9 ta bo‘lgan vektor)
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

# Har bir Buffer table’dan Buffer.data (ubyte vector) ni sug‘urib olamiz
blobs = []
ln = u32(buffers_vec)

for i in range(ln):
    ep = buffers_vec + 4 + 4*i
    table = ep + u32(ep)

    # Buffer table vtable
    b_vt_off = i32(table)
    b_vt = table - b_vt_off
    b_vlen = u16(b_vt)

    # Buffer’da 1 ta field bor: data
    data_field_off = u16(b_vt + 4) if b_vlen >= 6 else 0
    if data_field_off == 0:
        blobs.append(b"")
        continue

    field_pos = table + data_field_off
    vec = field_pos + u32(field_pos)
    blen = u32(vec)
    blob = data[vec + 4 : vec + 4 + blen]
    blobs.append(blob)

# 16 baytli UTF-16LE "k@3@y@!@" -> key = "k3y!"
key_blob = next(b for b in blobs if len(b) == 16 and b and b[1::2] == b"\x00"*8)
key = key_blob[0::2].replace(b"@", b"")  # b'k3y!'

# 36 baytli ciphertext
cipher = next(b for b in blobs if len(b) == 36)

# XOR -> zlib -> flag
xored = bytes(cipher[i] ^ key[i % len(key)] for i in range(len(cipher)))
flag = zlib.decompress(xored).decode()

print("key:", key.decode())
print("flag:", flag)
```

Ishga tushirish:

```bash
python3 solve.py
```

Kutiladigan chiqish:

- `key: k3y!`
- `flag: HTB{Cl0udy_C0r3_R3v3rs3d}`

---

## 4) Yakuniy flag

**HTB{Cl0udy_C0r3_R3v3rs3d}**
