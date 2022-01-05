# Tools

A list of tools and resources you may add to your hacking arsenal. This is also a great place to look if you're working on a particular problem and looking for a quick solution. Be sure to check out the reading resources on the main page, as it might give you some ideas for techniques to try out.

## Environment
If you haven't already, it's a good idea to set up a hacking environment first. Your current operating system might not support all of the below tools, and it's generally nice to work in an environment designed for working with cybersecurity. You can do this by setting up a virtual machine using a distro. If this is all new to you, it is recommended to use Kali Linux on Virtualbox.

### Virtual Machines
Virtualbox: https://www.virtualbox.org/
VMWare Workstation Pro: https://www.vmware.com/no/products/workstation-pro.html

### Distros
Kali: https://www.kali.org/ (Choose this one if you don't know better)
BlackArch: https://blackarch.org/ (Choose this one if you don't have any plans this weekend)
Parrot OS: https://www.parrotsec.org/ (Choose this one if you like saving resources)
Debian: https://www.debian.org/ (Choose this one if you love installing everything yourself)

### For Windows users
Windows Subsystem for Linux: https://docs.microsoft.com/en-us/windows/wsl/install (Linux compatibility layer for Windows, allows you to do linux stuff on your windows computer)
Windows Terminal: https://aka.ms/terminal (Like the command prompt, just way better. Supports tabs and emojis)

### Misc
OpenVPN: https://openvpn.net/ (Some platforms and CTFs require you to hook up to a remote network, which can be done with OpenVPN. This comes pre-installed on Kali and Parrot OS)
Obsidian: https://obsidian.md/ (Tool for taking notes, extremely useful when solving complex problems. Also nice if you encounter a similar problem later. Get into the habit of using this, you'll thank yourself later.)

## Web
BurpSuite: https://portswigger.net/burp
Jwt.io: https://jwt.io/
WPScan: https://wpscan.com/wordpress-security-scanner
sqlmap: https://sqlmap.org/
Certificate Search: https://crt.sh/
mitmproxy: https://mitmproxy.org/

## Stego
### Files
Binwalk: https://github.com/ReFirmLabs/binwalk
Strings: https://en.wikipedia.org/wiki/Strings_(Unix) (Can be combined with `grep` to filter results)
xxd: https://linux.die.net/man/1/xxd
HxD: https://mh-nexus.de/en/hxd/

### Images
Exiftool: https://exiftool.org/
Exiv2: https://www.exiv2.org/
ZSteg: https://github.com/zed-0xff/zsteg
Stegsolve: https://github.com/zardus/ctf-tools/blob/master/stegsolve/install
Steghide: http://steghide.sourceforge.net/
Foremost: https://tools.kali.org/forensics/foremost
zbarimg (For QR-koder/Barcodes): http://manpages.ubuntu.com/manpages/bionic/man1/zbarimg.1.html
OpenStego: https://www.openstego.com/
pngcheck: http://www.libpng.org/pub/png/apps/pngcheck.html
imageMagick, identify: https://imagemagick.org/script/identify.php
OutGuess: http://manpages.ubuntu.com/manpages/xenial/man1/outguess.1.html

### Sound
Universal Radio Hacker: https://github.com/jopohl/urh
Audacity: https://www.audacityteam.org/
Spectrum Analyzer: https://academo.org/demos/spectrum-analyzer/
Sonic Visualizer: https://www.sonicvisualiser.org/

## Forensics
Autopsy: https://www.sleuthkit.org/autopsy/
Wireshark: https://www.wireshark.org/

(Also be sure to check out tools under Stego and Pwn/RE)

## Hash-cracking
Hashcat: https://hashcat.net/hashcat/
John The Ripper: https://www.openwall.com/john/
Crack Station: https://crackstation.net/ (hash might appear in public database)
Rockyou.txt: https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt (best wordlist)
RainbowCrack: https://project-rainbowcrack.com/ (Use this if the hash isn't salted)

(If the hash cannot be cracked, try "pass the hash", or look up vulnerabilities in the hashing-algorithm. Ideally try this first, might save you time and eletricity :P)

## Crypto
### Modern cryptorgaphy (Basically anything that's an acronym)
SageMath: https://www.sagemath.org/
PyCryptodome: https://pycryptodome.readthedocs.io/en/latest/
z3-solver: https://pypi.org/project/z3-solver/
gmpy2 : https://pypi.org/project/gmpy2/
OpenSSL: https://www.openssl.org/
PGPDump: https://github.com/kazu-yamamoto/pgpdump (Extract data from an OpenPGP-key)

#### Asymmetric (RSA, ECC, Diffie-Hellman, etc.)
RSACtfTool: https://github.com/Ganapati/RsaCtfTool
FactorDB: https://factordb.com/ (Prime number database, check if a number is prime or if it has known factors)
Diffie-Hellman Backdoor: https://github.com/mimoo/Diffie-Hellman_Backdoor

#### Hashing
HashPump: https://github.com/bwall/HashPump

#### OTP and Stream ciphers (like AES-CTR)
MTP: https://github.com/CameronLonsdale/MTP

### Classical cryptography (Rot13, Vigenere, transposition ciphers, etc.)
CyberChef: https://gchq.github.io/CyberChef/
DCode: https://www.dcode.fr/
Boxentriq: https://www.boxentriq.com/code-breaking
Cryptii: https://cryptii.com/
Ciphey: https://github.com/Ciphey/Ciphey
Chepy: https://github.com/securisec/chepy

## Pwn/RE

### General
Frida: https://frida.re/

### Low-level/Binaries
GDB Peda: https://github.com/longld/peda
Ltrace: https://en.wikipedia.org/wiki/Ltrace
Strace: https://en.wikipedia.org/wiki/Strace
Ghidra: https://github.com/NationalSecurityAgency/ghidra/releases
IDA Pro: https://hex-rays.com/ida-pro/
Radare2: https://rada.re/n/
Cutter: https://cutter.re/
Angr: https://angr.io/

### Java/Android
Java Decompiler: http://java-decompiler.github.io/
dex2jar: https://github.com/pxb1988/dex2jar
jadx: https://github.com/skylot/jadx
Android Studio: https://developer.android.com/studio (The AVD emulator is especially useful for dynamic analysis)

### Python (.pyc-files)
Uncompyle6: https://pypi.org/project/uncompyle6/

## Enum/recon
Nmap: https://nmap.org/
Dirbuster: https://www.kali.org/tools/dirbuster/
Certificate Search: https://crt.sh/
PEASS (winpeas og linpeas): https://github.com/carlospolop/PEASS-ng
Low-Hanging Fruit: https://github.com/blindfuzzy/LHF
WPScan: https://wpscan.com/wordpress-security-scanner
(protip: run `sudo -l` if you have foothold on a UNIX-system (linux/mac), this may give you an indicator for potential vectors for local privilidge escalation, as it lists executables and scripts you may run as root using sudo)

## Exploitation
Metasploit: https://www.metasploit.com/ (This tool is pre-installed on Kali, and comes with thousands of exploits for a wide range of known vulnerabities)
GTFOBins: https://gtfobins.github.io/
Reverse Shell Generator: https://www.revshells.com/

## OSINT

### General
OSINT Framework: https://osintframework.com/
Recon-ng: https://github.com/lanmaster53/recon-ng

### People finding
Whitepages: https://www.whitepages.com/
GHunt: https://github.com/mxrch/GHunt
Sherlock: https://github.com/sherlock-project/sherlock
Namechk: https://namechk.com/
That's Them: https://thatsthem.com/
PimEyes: https://pimeyes.com/en (Allows you to identify people in photos, works terrifyingly well)

### Data analysis
Maltego: https://www.maltego.com/
Spiderfoot: https://www.spiderfoot.net/

### Misc
Shodan: https://www.shodan.io/ (Allows you to look up severs online)
SunCalc: http://suncalc.net/ (Use the power of the sun to find out where and when a photo is taken)
