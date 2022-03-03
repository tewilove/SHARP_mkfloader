# Abstract
> SHARP Android devices support loading code inside their bootloader during boot.
> Strings from their SBLs shows that there were "CARRIER LOADER", "FLOADER", "SDLOADER".
> And before the year 2015 or so the code to load is encrypted but not signed, cheers.
> Image sending customized LK to enter fastboot mode.
# Usage
## Compile and convert to floader format
### Example crash.S
```
start:
    ldr r0, abort
    ldr r0, [r0]
    bx r0
abort:
.word 0xdeadbeef
```
## Compile
```
arm-eabi-gcc -c -o crash.o crash.S
```
## Generate bare mental code
```
arm-eabi-objcopy -O binary crash.o crash.bin
```
## Encrypt
```
mkfloader -d 303SH -i crash.bin -o crash.ldr
```
## Run
```
./floader.py --boot crash.ldr
```
# Advanced topic
## Extract floader AES key:
```
shell@SG502SH:/ # /data/local/tmp/shdarea r 2 0x5800 128                       
02:00005800: 4F 78 49 65 46 56 6F 54 57 67 30 68 45 6B 53 30 
02:00005810: 03 00 4B 62 64 31 7A 77 77 66 49 33 67 78 33 67 
02:00005820: 46 78 39 74 6B 69 51 70 63 36 33 69 46 4B 68 4E 
02:00005830: 34 56 FF FF FF FF FF FF FF FF FF FF FF FF FF FF 
02:00005840: FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 
02:00005850: FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 
02:00005860: FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 
02:00005870: FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
```
## floader.py --boot
| Chipset | Address | Alternative Address |
| ------ | ------ | ------ |
| msm8960 | 0x80200000 | 0x2E000000 |
| msm8974 | 0x20000000 | 0xF8002000 |