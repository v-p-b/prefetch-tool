# Windows KASLR Prefetch Tool
A proof-of-concept tool for bypassing KASLR (kernel ASLR) on Windows 11. Inspired by [EntryBleed](https://www.willsroot.io/2022/12/entrybleed.html) for Linux.

**This branch** implements a technique described [here](https://scrapco.de/blog/visualizing-prefetch-infoleaks-to-defeat-kaslr.html). For testing, it disables CPU detection, and runs the new infoleak algorithm. When executed as admin, it uses the `EnumDeviceDrivers` API to get the kernel base for comparison. When executed with the `-pt` command line switch, it collects prefetch timing data and writes them as a series of .BMP-s to the CWD. Resulting images can be upscaled and converted to an animated gif with ImageMagick:

```bash
for bmp in pt_*.bmp;do convert "$bmp" -flip -scale 1024x big_"$bmp"; done
convert -delay 10 bi_*.bmp out.gif
```

The new code is very messy (at minimum integer overflows are everywhere) as I implemented new ideas as I went before any planning or proper refactoring, sorry about that!

The code is now also available as a [static library](https://github.com/v-p-b/prefetch-lib/) for easier embedding.

**Original README continues:**

This tool was developed as part of an [exploit targetting Windows 11 24H2](https://exploits.forsale/24h2-nt-exploit/). I am not a side-channel expert at all, so this was very much new territory for me and the code is very hacky 😳 Help improving reliability for different CPU types would be much appreciated.

I have done limited testing with the machines at my disposal. I found the techniques I implemented to be quite reliable on modern Intel CPUs, but much less so on AMD.

### CPU Support
| CPU | Status |
| ----------- | ----------- |
| Intel | 🟢 Reliable |
| AMD | 🟡 Flaky |
