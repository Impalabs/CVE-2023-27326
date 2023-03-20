# Parallels Desktop VM Escape

This repository contains an exploit for a [Parallels Desktop](https://www.parallels.com/products/desktop/) vulnerability which has been assigned CVE-2023-27326. This vulnerability allows local attackers to escalate privileges on affected installations of Parallels Desktop.

The exploit was tested on Parallels Desktop version 18.0.0 (53049), and the vulnerability was patched in the 18.1.1 (53328) [security update](https://kb.parallels.com/125013).

## Vulnerability Details

The specific flaw exists within the *Toolgate* component. The issue results from the lack of proper validation of a user-supplied path prior to using it in file operations. An attacker can leverage this vulnerability to escalate privileges and execute arbitrary code in the context of the current user on the host system.

The full details of the vulnerability can be found in the accompanying [blog post](https://blog.impalabs.com/2303_advisory_parallels-desktop_toolgate.html).

## Credits

The vulnerability was discovered and exploited by Alexandre Adamski of [Impalabs](https://impalabs.com). The boiler plate code of the kernel module is taken from [RET2 Systems](https://ret2.io/)'s [Pwn2Own 2021 exploit](https://github.com/ret2/Pwn2Own-2021-Parallels/).

## License

The contents of this repo are licensed and distributed under the MIT license.
