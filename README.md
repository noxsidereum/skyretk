# skyretk
Skyrim Reverse Engineering Toolkit (GOG)

by noxsidereum

#### Credit
The two projects currently here, `dump_functions` and `dump_rtti`, are
essentially updated and expanded 64 bit versions of the analogous 32 bit projects 
created by Himika:
https://github.com/himika/libSkyrim. E.g. I've updated the RTTI processing to
use relative instead of absolute addresses where appropriate. And there's lots of
code documentation.

I've also benefited considerably from perusal of Igor Skochinsky's
article at http://www.openrce.org/articles/full_view/23 and by playing
around with the fantastic IDA dissembler, https://hex-rays.com/ida-pro/ida-disassembler/.

If time permits, I intend to expand this work further and add more powerful
RE capabilities tailored to the Skyrim executable.

#### Requires

SKSE 2.2.3

Skyrim 1.6.659 (GOG edition) - because my address offsets are currently hardcoded.

#### Usage

1. Put the DLL files into a new or existing mod
2. Load Skyrim via the SKSE loader, wait until main menu appears then quit.
3. If it all worked correctly, the RTTI and Papyrus native function details will 
have been dumped to `dump_rtti.log` and `dump_functions.log` respectively, in your 
`My Games/Skyrim Special Edition GOG/SKSE` directory.

### Note

The purpose of this work is simply for me to learn the basics of RE and have some fun hacking Skyrim.

I do not and never will support software piracy. If you want to play or mod this great game, do the right thing and buy it 
from GOG, Epic or wherever else. It really doesn't cost much.

### Licence
MIT Licence. Basically do whatever you want with this code, but: (a) please include attributions for
Himika and I in any derivative products; and (b) don't blame me if it doesn't do what you want, or breaks something.
