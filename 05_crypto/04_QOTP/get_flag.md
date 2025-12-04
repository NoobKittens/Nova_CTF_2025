# QOTP

![](attachments/Pasted%20image%2020251130183425.png)

# Challenge: QOTP (Quantum One Time Pad)

**Category:** Crypto  
**Flag:**  
Nova_Ctf{qUAn7um_de73CtoRS_2025}

---

## 1. What's the Challenge?

So, we started off with a generator script hints.txt and the actual challenge file chal.txt. Basically, it's a simulation of a Quantum One Time Pad, but with a twist—it's "noisy."

## 2. Breaking Down the Encryption

Here’s what's happening under the hood:

1. **Prep Work:** They take the message, tack on a checksum, and turn the whole thing into bits.
2. **Repeat, Repeat:** They repeat those bits 4 times.
3. **The Scramble:** Then, they generate 1200 encrypted versions!
    - They pick a random **basis** (either 0 or 1).
    - If the **basis** is 0, they send the message bit exactly as is.
    - If the **basis** is 1, they flip the message bit (0 becomes 1, 1 becomes 0).
    - **The Catch:** There's artificial "noise." Every single bit has a 20% chance of flipping on its own, just to mess with us.


## 3. How We Solved It

Since we have a ton of samples (1200 of them!) and the error rate is well under 50%, we don't need magic—we just need some basic statistics.

### Getting the Message Back

For every single bit position, we did this:
1. We looked at all 1200 samples.
2. We "normalized" what we received based on the basis.
    - If the basis was 1 (meaning it was flipped on purpose), we flipped it back.
    - If the basis was 0, we left it alone.
3. Because of the noise, our result is right about 80% of the time.
4. We just took a **majority vote**. Whichever bit showed up the most was almost certainly the original message bit.

## Cleaning It Up
1. We stitched all the recovered bits back together.
2. Converting that back to text gave us this string:
    - `{tXDq7xp_gh73FwrUV_2025}`
3. The challenge dropped a hint about "shift shift shift," so we figured it was a classic Caesar cipher. We shifted everything back by 3, and boom!
    - `{tXDq7xp_gh73FwrUV_2025}` turned into `{qUAn7um_de73CtoRS_2025}`.

## 4. The Flag

Wrap it up in the standard format, and we're done!  
Nova_Ctf{qUAn7um_de73CtoRS_2025}