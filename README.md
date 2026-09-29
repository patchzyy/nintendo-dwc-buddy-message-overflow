# Nintendo DWC buddy-message stack buffer overflow

Discovered by [patchzy](https://github.com/patchzyy)

CWE-121: Stack-based Buffer Overflow.

The vulnerability affects games using the Nintendo DWC buddy-message handler, `DWCi_GPRecvBuddyMessageCallback`. A crafted message can overwrite the game's stack and lead to remote code execution.

## The bug

The handler derives a field length from the received message and passes it to `strncpy`. The length check happens **after the copy**, when stack corruption has already occurred:

(simplified)
```c
strncpy(buffer, field, length);
if (length > 10)
    reject_message();
```

Original PPC from MKWii PAL (`0x800D36D0`):

```asm
subf    r29, r30, r3     # Get the field length
mr      r4, r30          # Source: message field
mr      r5, r29          # Copy count: unchecked length
addi    r3, r1, 0x08     # Destination: stack buffer
bl      0x800131E0       # strncpy: copy into the buffer
cmplwi  r29, 10          # Only now check the length
bgt     0x800D3704       # Reject if too long (woops too late)
```

## The fix

Bound the copy length before calling `strncpy`. The [fix from wiilink](https://github.com/WiiLink24/wfc-patcher-wii/commit/f5de8fb96558dd02ed5160c51c4666e7c754b403) replaces the instruction that supplies the copy count:

```asm
# Before
mr      r5, r29

# After
rlwinm  r5, r29, 0, 29, 31
```

`r29` contains the original length and `r5` is the length argument to `strncpy`.
The replacement computes `r5 = r29 & 7`, restricting the copy to 0–7 bytes.

The same approach be applied to other DWC builds by locating the corresponding copy-count instruction and checking the register allocation.
