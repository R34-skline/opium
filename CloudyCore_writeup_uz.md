# CloudyCore

## Challenge ma'lumotlari

- **Level:** Medium  
- **Kategoriya:** Reverse  
- **Tavsif:**  
  Twillie, xotira-asrovchi, qor sharlaridan birini “orqaga qaytarayotgan” paytda yovuzona pichirlashni eshitib qoldi. Qaroqchi Starshard’ning haqiqiy xotirasini shu kichkina xotira yadrosi (.tflite) ichiga yashirganini maqtanib aytayotgan ekan. U shu qadar ishonchli ediki, hech kim “zerikarli” ML faylni reverse qilishni o‘ylamaydi, deb kulibdi. U “kimdir urinsa” deb oxirgi bo‘lakni juda sodda XOR bilan aralashtirib qo‘yganini ham aytgan. Kalitni toping, kulgili darajada sodda XOR’ni teskari qiling va xotirani tiklang.

---

## Fayllar

- `rev_cloudy_core.zip`

---

## Yechim (step-by-step)

### 1) ZIPni ochish

```bash
unzip rev_cloudy_core.zip -d cloudycore
cd cloudycore
ls -la
```

Odatda ichidan TensorFlow Lite model fayli chiqadi:

- `snownet_stronger.tflite`

---

### 2) Fayl turini aniqlash

```bash
file snownet_stronger.tflite
```

Bu `.tflite` — FlatBuffers asosidagi konteyner model.

Tezkor “hint” uchun `strings` ishlatamiz:

```bash
strings -n 4 snownet_stronger.tflite | head -n 80
```

---

### 3) Reverse mantiqi (nima bo‘layapti?)

`.tflite` fayl ichida (FlatBuffers tuzilmasida) **Buffers** degan ro‘yxat bo‘ladi. U yerda:

- tensorlar (weight/constant)
- ba’zan metadata yoki qo‘shimcha “blob”lar

Ushbu challenge’da bizga **ikkita** buffer muhim:

1) **16 baytli** blob — UTF-16LE ga o‘xshaydi:  
   - baytlar ko‘rinishi: `k\x00@\x003\x00@\x00y\x00@\x00!\x00@\x00`  
   - matn: `k@3@y@!@`  
   - `@`larni olib tashlasak → **kalit = `k3y!`**

2) **36 baytli** blob — random ko‘rinadi → bu **ciphertext**

Challenge tavsifida “oddiy XOR” deyilgan, demak:
- ciphertext’ni `k3y!` (takrorlanadigan) bilan XOR qilamiz.

XORdan keyin natija boshida `0x78 0x9c` chiqadi — bu odatda **zlib** stream header’iga mos keladi.
Shuning uchun:
- XOR natijasini `zlib.decompress()` qilamiz → flag chiqadi.

---

## Solve skript

Quyidagini `solve.py` qilib saqlang ( `snownet_stronger.tflite` bilan bitta papkada):

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

# buffers vektorini topish:
# (bu challenge’da uzunligi 9 bo‘lgan vektor chiqadi; root field’larni skan qilib topamiz)
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

# Har bir Buffer table’dan Buffer.data (ubyte vector) ni sug‘urib olish
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

# 16 baytli UTF-16LE-ga o‘xshash: "k@3@y@!@" -> kalit = "k3y!"
key_blob = next(b for b in blobs if len(b) == 16 and b and b[1::2] == b"\x00"*8)
key = key_blob[0::2].replace(b"@", b"")  # b'k3y!'

# 36 baytli ciphertext
cipher = next(b for b in blobs if len(b) == 36)

# XOR -> zlib -> flag
xored = bytes(cipher[i] ^ key[i % len(key)] for i in range(len(cipher)))
flag = zlib.decompress(xored).decode()

print("kalit:", key.decode())
print("flag:", flag)
```

Ishga tushirish:

```bash
python3 solve.py
```

---

## Flag

`HTB{Cl0udy_C0r3_R3v3rs3d}`
