# Sigga - sigmaker for Ghidra
*The name "Sigga" is a mix of the german word "Digga" (roughly translates to "brother"), and "Signature"*

Sigga is a Ghidra script for creating x86/x64 function signatures. It is well documented and easily maintainable.

## Features
This script contains the core functionality of signature creation, plus advanced features to handle complex, real-world binaries where other tools might fail.

- **Guided Generation:** Opens a small settings dialog so you can choose function-start vs current-address scanning, allow or skip XRef fallback, and optionally tune scan limits.
- **Auto-Cascading Tiers:** Automatically retries with lower strictness or different strategies if a unique signature cannot be found initially.
- **Practical Search:** Instruction-aligned candidates are ranked by shortest length, concrete-byte density, then offset. Search scope is executable memory only.
- **Resolvable XRef Fallback:** If direct code is too generic, Sigga can use a direct `CALL`, direct `JMP`, or x64 RIP-relative `LEA` reference and prints exact rel32 resolver metadata.
- **x86/x64-aware Masking:** Masks common relative branches, relocations, RIP-relative operands, and absolute mapped references without trying to decode every possible instruction form.
- **Professional Offset Signatures:** The script produces industry-standard signatures with offsets, avoiding problematic leading wildcards.

Sigga measures uniqueness in executable memory of the opened program. Its confidence score is heuristic; validate generated patterns against a later build before relying on patch resistance.

## Installation
To get the latest version with all performance fixes, download **Sigga.java** directly from the source:

👉 **[Download Sigga.java](https://github.com/lexika979/Sigga/blob/main/Sigga.java)**

*(Note: The [Releases page](https://github.com/lexika979/Sigga/releases) may not always contain the most recent logic updates.)*

**Setup:**
1.  Place `Sigga.java` inside `C:/Users/(your username)/ghidra_scripts`. If the folder does not exist yet, create it first.
2.  Open Ghidra and the Script Manager.
3.  Open the "Functions" folder.
4.  Right click "Sigga" and assign a keybind (I recommend *Ctrl-Alt-S*).

*Troubleshooting: In case Sigga does not show up in the list, try to create a new script through the UI and immediately delete it again to force a refresh.*

## Sigga in action

Select any function (or place your cursor inside one) and press your assigned keybind.

Sigga will ask where the pattern should start, then analyze the function, find the best possible signature (checking Direct, XRef, and Fallback tiers), and **automatically copy it to your clipboard**.

Results are printed to the **Ghidra Console**:

```text
Sigga: Analyzing FUN_00975aa0 @ 00975aa0 (FUNCTION_START)
==================================================
 SIGGA SUCCESS - Tier 1 (Direct / Strong Head)
==================================================
Signature:  48 83 EC 28 48 8B 05 ? ? ? ? 48 85 C0
Address:    00975aa0
Offset:     +0
Heuristic confidence: 100/100
==================================================
>> Copied to clipboard.
```

## Contributing/Bug reporting

I **highly** appreciate anyone that wants to contribute by fixing bugs or adding new functionality!

Feel free to open a pull request, but please make sure your changes/new code are properly documented and formatted :)

## Credits
- **lexika** - Original author and creator of Sigga.
- **[@Krixx1337](https://github.com/Krixx1337)** - Major architectural overhaul, adding the XRef fallback, sliding window search, and advanced stability analysis.
- **outercloudstudio** - Fixed a bug with the original wildcard placement.

## Limits

- Supports 32-bit and 64-bit x86 programs only.
- Generates single-build heuristics, not a cross-version compatibility guarantee.
- Tier 3 signatures require applying printed resolver metadata to recover the referenced function.
