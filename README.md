# Sigga - sigmaker for Ghidra
*The name "Sigga" is a mix of the german word "Digga" (roughly translates to "brother"), and "Signature"*

Sigga is a robust Ghidra script to create function signatures. It is well documented and easily maintainable.

## Features
This script contains the core functionality of signature creation, plus advanced features to handle complex, real-world binaries where other tools might fail.

- **One-Click Generation:** Runs immediately without configuration dialogs.
- **Auto-Cascading Tiers:** Automatically retries with lower strictness or different strategies if a unique signature cannot be found initially.
- **Fast & Efficient:** A modern sliding-window algorithm with **instruction alignment enforcement** ensures signatures are generated instantly, even for large or generic functions.
- **Signature by Cross-Reference (XRef) Fallback:** If a function's code is too generic to be unique (like a compiler-generated `memcpy`), Sigga will automatically create a signature for the code that *calls* it. This allows it to succeed where many other sigmakers fail.
- **Intelligent Stability Analysis:** The logic for what to wildcard is highly advanced, including static data references (`[RIP + disp]`) to create far more robust signatures that are more likely to survive game updates.
- **Professional Offset Signatures:** The script produces industry-standard signatures with offsets, avoiding problematic leading wildcards.

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

Sigga will immediately analyze the function, find the best possible signature (checking Direct, XRef, and Fallback tiers), and **automatically copy it to your clipboard**.

Results are printed to the **Ghidra Console**:

```text
Sigga: Analyzing FUN_00975aa0 @ 00975aa0
==================================================
 SIGGA SUCCESS - Tier 1 (High Stability, Direct)
==================================================
Signature:  48 83 EC 28 48 8B 05 ? ? ? ? 48 85 C0
Address:    00975aa0
Offset:     +0
Quality:    100/100
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

## Known bugs/Issues

- None.
