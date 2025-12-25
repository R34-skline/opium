# Starshard Reassembly — Write-up

 ## Challenge info

```text
Level: Easy
Category: reverse

Tavsif: Twillie Snowdrop, the village's Memory-Minder, has discovered that one of her enchanted snowglobes has gone cloudy , its Starshard missing and its memories scrambled. To restore the scene within, you must provide the correct sequence of "memory shards". The binary will accept your attempt and reveal whether the Starshard glows once more. Can you decipher the snowglobe’s secret and bring the memory back to life?
```

## Solution

## 1) Fayllar va tayyorgarlik

Fayl ichida nima borligini ko'ramiz:

```bash
ls -la rev_starshard_reassembly/
```

Natija shunaqa chiqadi:

- `memory_minder` — asosiy binary

Binary formatini tekshiramiz:

```bash
file rev_starshard_reassembly/memory_minder
```

Natijada shu chiqadi:

- `Mach-O 64-bit x86_64 executable, flags:<|DYLDLINK|PIE>`

Bu degani: **macOS** uchun compiled binary. Linux’da uni bevosita run qilish shart emas — biz **statik tahlil** qilamiz.

---

## 2) Binary Go ekanini aniqlash

Go binarylarda ko‘pincha “Go build ID” kabi yozuvlar bo‘ladi:

```bash
strings -a rev_starshard_reassembly/memory_minder | grep -i "go build" | head
```

Shu bilan binary **Golang** ekanini bilib oldik.

---

## 3) Symbol’larni ko‘rish (`go tool nm`)

Go toolchain Mach-O’ni o‘qiy oladi. Avval umumiy symbol’lar:

```bash
go tool nm rev_starshard_reassembly/memory_minder | head
```

Keyin faqat `main.` bilan boshlanuvchi symbol’lar:

```bash
go tool nm rev_starshard_reassembly/memory_minder | grep -E " main\." | head -n 80
```

Bu yerda juda qiziq pattern chiqadi:

- `main.(*R0).Expected`
- `main.(*R0).Match`
- `main.(*R1).Expected`
- `main.(*R1).Match`
- ...
- `main.(*R27).Expected`
- `main.(*R27).Match`

**Xulosa:** Flag **R0..R27** degan bo‘laklarga bo‘lingan, va har bir `Expected` funksiyasi **bitta qiymat (harf)** qaytarayotganga o‘xshaydi.

---

## 4) `Expected` funksiyalarini disassemble qilish (`go tool objdump`)

Masalan, R0:

```bash
go tool objdump -s 'main.\(\*R0\)\.Expected' rev_starshard_reassembly/memory_minder | head -n 60
```

Menda shu joy muhim edi:

```
MOVL $0x48, AX
```

`0x48` — ASCII’da **'H'**.

Demak:
- Har bir `Expected` ichida `MOVL $0x.., AX` kabi **immediate constant** bor,
- Biz shu constant’larni yig‘ib, flag’ni chiqaramiz.

Tez ko‘rish uchun grep:

```bash
go tool objdump -s 'main.\(\*R0\)\.Expected' rev_starshard_reassembly/memory_minder | grep MOVL
```

---

## 5) Flagni olish uchun `python` script

```bash
import subprocess, re

binpath = "rev_starshard_reassembly/memory_minder"
out_chars = []

for i in range(28):  # R0..R27
    sym = f"main.\(\*R{i}\)\.Expected"
    cmd = f"go tool objdump -s '{sym}' {binpath}"
    text = subprocess.check_output(cmd, shell=True, text=True)

    m = re.search(r"MOVL\s+\$0x([0-9a-fA-F]+),\s*AX", text)
    if m:
        out_chars.append(chr(int(m.group(1), 16)))
        continue

    m = re.search(r"MOVL\s+\$([0-9]+),\s*AX", text)
    if m:
        out_chars.append(chr(int(m.group(1))))
        continue

print("".join(out_chars))
```
Uni `run` qilish

```bash
python3 your_file_name.py
---

## 6) Natija (Flag)

Script natijasi:

```
HTB{M3M0RY_R3W1D_SNOWGL0B3}
```


