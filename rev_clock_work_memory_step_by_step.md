# Clock Work Memory

 ## Challenge info

```text
Level: very easy
Category: reverse

Tavsif: Twillie's "Clockwork Memory" pocketwatch is broken. The memory it holds, a precious story about the Starshard, has been distorted. By reverse-engineering the intricate "clockwork" mechanism of the `pocketwatch.wasm` file, you can discover the source of the distortion and apply the correct "peppermint" key to remember the truth.
```

## Solution

### 1) ZIP ichidagi fayllarni ko‘rish va chiqarib olish

```bash
unzip -l /mnt/data/rev_clock_work_memory.zip
unzip -q /mnt/data/rev_clock_work_memory.zip -d /mnt/data
ls -la /mnt/data/rev_clock_work_memory
```

Bu yerda asosiy fayl:
- `/mnt/data/rev_clock_work_memory/pocketwatch.wasm`

---

## 21) WASM ichidan eksport qilingan funksiyalarni topish (qaysi funksiya “flag check” qiladi?)

Endi minimal WASM parser yozib, **Export section**ni o‘qish va eksportlarni chiqarish kerak:

```bash
python3 - << 'PY'
from pathlib import Path
import io

data = Path("/mnt/data/rev_clock_work_memory/pocketwatch.wasm").read_bytes()
bio = io.BytesIO(data)
bio.read(8)  # magic + version

def uleb(b):
    r = 0
    s = 0
    while True:
        x = b.read(1)[0]
        r |= (x & 0x7f) << s
        if x < 0x80:
            return r
        s += 7

# sectionlarni yig‘amiz
secs = []
while True:
    t = bio.read(1)
    if not t:
        break
    sid = t[0]
    size = uleb(bio)
    payload = bio.read(size)
    secs.append((sid, payload))

sec = dict(secs)

# Export section id=7
exp = io.BytesIO(sec[7])
count = uleb(exp)

exports = []
for _ in range(count):
    nlen = uleb(exp)
    name = exp.read(nlen).decode()
    kind = exp.read(1)[0]   # 0=func, 2=memory, ...
    idx  = uleb(exp)
    exports.append((name, kind, idx))

print("Exports:")
for e in exports:
    print(" ", e)
PY
```

Natijada `check_flag` eksport qilingani ko'rinadi — demak flagni tekshiradigan logika shu funksiya ichida.

---

## 3) Data segmentni topish (WASM memoryga yozilgan yashirin baytlar)

Keyingi qadam: WASM’ning **Data section (id=11)** ichidan aktiv data segmentni o‘qish.

Bu challengeda data segment **offset = 1024** ga yozilgan va uzunligi **23 bayt**.

```bash
python3 - << 'PY'
from pathlib import Path
import io

data = Path("/mnt/data/rev_clock_work_memory/pocketwatch.wasm").read_bytes()
bio = io.BytesIO(data)
bio.read(8)

def uleb(b):
    r = 0
    s = 0
    while True:
        x = b.read(1)[0]
        r |= (x & 0x7f) << s
        if x < 0x80:
            return r
        s += 7

secs = []
while True:
    t = bio.read(1)
    if not t:
        break
    sid = t[0]
    size = uleb(bio)
    payload = bio.read(size)
    secs.append((sid, payload))

sec = dict(secs)

# Data section id=11
d = io.BytesIO(sec[11])
segcount = uleb(d)
flags = d.read(1)[0]        # 0 => active, memidx implicit 0

# init expr: i32.const <offset> end
op = d.read(1)[0]           # 0x41 => i32.const
assert op == 0x41
offset = uleb(d)
end = d.read(1)[0]          # 0x0b => end
assert end == 0x0b

size = uleb(d)
blob = d.read(size)

print("segcount =", segcount)
print("flags    =", flags)
print("offset   =", offset)
print("size     =", size)
print("data(hex)=", blob.hex())
PY
```

Chiqqan 23 bayt — bu **shifrlangan/obfuscate qilingan** string baytlari.

---

## 4) `check_flag` ichidan “kalit”ni topish (TOCK)

Endi `check_flag` funksiyasi bytecode’ini tekshirib, unda `i32.const 0x4b434f54` konstantasi borligini topamiz.

E’tibor berish kerak bo'lgan joyi shuki WASM little-endian store qilgani uchun bu qiymat ASCII’da **"TOCK"** bo‘lib chiqadi (`T O C K`).

Quyidagi skript Code section’dan `check_flag` tanasini olib, `i32.const` konstantalar ichidan aynan `0x4b434f54`ni qidiradi:

```bash
python3 - << 'PY'
from pathlib import Path
import io

data = Path("/mnt/data/rev_clock_work_memory/pocketwatch.wasm").read_bytes()
bio = io.BytesIO(data)
bio.read(8)

def uleb(b):
    r = 0
    s = 0
    while True:
        x = b.read(1)[0]
        r |= (x & 0x7f) << s
        if x < 0x80:
            return r
        s += 7

secs = []
while True:
    t = bio.read(1)
    if not t:
        break
    sid = t[0]
    size = uleb(bio)
    payload = bio.read(size)
    secs.append((sid, payload))

sec = dict(secs)

# Code section id=10: funksiya body’lari
c = io.BytesIO(sec[10])
fn_count = uleb(c)

bodies = []
for _ in range(fn_count):
    sz = uleb(c)
    bodies.append(c.read(sz))

check_flag_body = bodies[1]  # export index 1 bo‘lgani uchun (bu challenge’da) 2-funksiya

def sleb(bs, pos):
    r = 0
    s = 0
    while True:
        b = bs[pos]
        pos += 1
        r |= (b & 0x7f) << s
        s += 7
        if b < 0x80:
            if s < 32 and (b & 0x40):
                r |= - (1 << s)
            return r, pos

targets = {0x4b434f54: "TOCK"}
for i in range(len(check_flag_body) - 1):
    if check_flag_body[i] == 0x41:  # i32.const
        v, _ = sleb(check_flag_body, i + 1)
        if v in targets:
            print("Found i32.const", hex(v), "=>", targets[v], "at byte offset", i)
PY
```

Shu bilan **kalit = `TOCK`** ekanini aniqlanadi.

---

## 5) Flagni qayta tiklash (XOR)

`check_flag` logikasi  shunday:
- data segmentdagi baytlar (`secret[i]`)
- `"TOCK"` kalitini 4 bayt bo‘yicha aylantirib (`key[i % 4]`)
- `flag[i] = secret[i] XOR key[i % 4]`

Demak flagni olish uchun faqat XOR qilish yetarli.

```bash
python3 - << 'PY'
secret = bytes.fromhex("1c1b0130237b30260b3d703d0b7e3014377f7327756e3e")
key = b"TOCK"
flag = bytes(secret[i] ^ key[i & 3] for i in range(len(secret)))
print(flag.decode())
PY
```

---

## 6) Yakuniy natija

Shu yo'l bilan flag chiqadi:

```
HTB{w4sm_r3v_1s_c00l!!}
```

---
