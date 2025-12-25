# Disguised

## Challenge info

```text
Event: HTB University CTF 2025
Challenge: Disguised
Category: Crypto
Difficulty: Medium
Points: 1000

Description:
At the Frostgate of Tinselwick, a protective hearth-protocol grants enchanted tokens to its visitors.
Its wintry cipher and shifting session marks guard the final Starshard scroll—but the system's snowy
protections may not be as sturdy as they appear. This is the last step in unraveling the Starshard's
disguised retreat.

Remote:
154.57.164.81:31918
```

## Solution

1. **Understanding the token format**

   Registering a user returns a “Hearth Token”. Looking at the server logic, the plaintext being encrypted is a JSON structure:

   ```json
   {"s": "<snow mark (hex)>", "i": <uid>}
   ```

   ![server](/home/martian/Pictures/Screenshots/Screenshot_20251225_164528.png)

2. **AES-like cipher with only 2 rounds**

   The cipher mirrors AES building blocks:
   - AES S-Box
   - ShiftRows
   - MixColumns over GF(2^8)
   - RoundKey XOR

   The critical flaw is the number of rounds: **only 2**. With so little diffusion, relationships between plaintext differences and ciphertext differences remain exploitable.

3. **Collecting chosen-plaintext samples**

   I registered multiple users (e.g., 12) to collect several (uid, token) pairs. Since the JSON structure is known, the last plaintext block (including PKCS#7 padding) can be computed offline.

   [![token](/home/martian/Pictures/Screenshots/Screenshot_20251225_170039.png)

4. **Recovering round keys column-by-column**

   With two rounds, we can attack the cipher per column:

   - Extract the last 16 bytes of the ciphertext (last block).
   - Compute XOR differences between blocks from different UIDs.
   - Apply `InvMixColumns` to translate column differences back to the “S-Box output difference” space.
   - For each byte, brute-force candidates satisfying:

     ```text
     SBOX[p ^ k] XOR SBOX[p' ^ k] == delta
     ```

   - Validate candidates across additional UIDs to collapse the candidate set.

   This recovers the two round keys (**rk0** and **rk1**).

   ![recovering keys](/home/martian/Pictures/Screenshots/Screenshot_20251225_170155.png)

5. **Mapping round keys back to the master key**

   The system also derives the snow mark as:

   ```text
   snow = SHAKE256(KEY || username || uid).digest(64).hex()
   ```

   After recovering rk0/rk1, I enumerated plausible master-key layouts (row/column ordering, transposes, etc.) and re-encrypted a known user’s token until it matched the server-issued token. That uniquely identifies the real **KEY**.
   
   ![recover token](/home/martian/Pictures/Screenshots/Screenshot_20251225_171422.png)


6. **Forging the admin token**

   Admin target:   - username: `TinselwickAdmin`
   - uid: `0`

   Steps:
   - Compute `admin_snow` from the recovered KEY.
   - Encrypt:

     ```json
     {"s":"<admin_snow>","i":0}
     ```

   - Submit the forged token to the login endpoint.
     
   ![admin](/home/martian/Pictures/Screenshots/Screenshot_20251225_171446-1.png)

7. **Flag**

   ```text
   HTB{0n3_r0und_d1sgu1s3d_A3S_1s_v3ry_fun_t0_cr4ck_3a6a8d277ffdb34fc72725fe06f6c1db}
   ```

---

### Notes for learners

- Full AES uses 10/12/14 rounds; this attack works because the challenge uses **only 2 rounds**.
- “Chosen plaintext” here means we control registrations and can gather many samples with predictable plaintext structure.
- MixColumns lets us work column-wise, which drastically reduces brute-force search space.
