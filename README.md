# Sigga - sigmaker for Ghidra
*The name "Sigga" is a mix of the german word "Digga" (roughly translates to "brother"), and "Signature"*

Sigga is a robust Ghidra script to create function signatures. It is well documented and easily maintainable.

## Features
This script contains the core functionality of signature creation, plus advanced features to handle complex, real-world binaries where other tools might fail.

- **One-Click Generation:** Runs immediately without configuration dialogs.
- **Auto-Cascading Tiers:** Automatically retries with lower strictness or different strategies if a unique signature cannot be found initially.
- **Fast & Efficient 'Sliding Window' Search:** A modern algorithm finds the smallest possible signature and is exponentially faster on large binaries than the original version.
- **Signature by Cross-Reference (XRef) Fallback:** If a function's code is too generic to be unique (like a compiler-generated `memcpy`), Sigga will automatically create a signature for the code that *calls* it. This allows it to succeed where many other sigmakers fail.
- **Intelligent Stability Analysis:** The logic for what to wildcard is highly advanced, including static data references (`[RIP + disp]`) to create far more robust signatures that are more likely to survive game updates.
- **Professional Offset Signatures:** The script produces industry-standard signatures with offsets, avoiding problematic leading wildcards.

## Installation
To install Sigga, simply [download the latest release](https://github.com/lexika979/Sigga/releases) and put *Sigga.java* inside C:/Users/(your username)/ghidra_scripts. If the folder does not exist yet, create it first. - That's it!

I highly recommend binding Sigga to a shortcut to save yourself a lot of clicks. You can do so like this:

1) Open Ghidra and the Script manager:

![](https://i.imgur.com/usOQWPh.png)

2) Open the "Functions" folder:

![](https://i.imgur.com/sIxclgU.png)

3) Right click "Sigga" and assign a keybind (I recommend *Ctrl-Alt-S*):

![](https://i.imgur.com/N7kSe4F.png)

Troubleshooting: In case Sigga does not show up in the list, try to create a new script through the UI and immediately delete it again. That should force Ghidra to acknowledge the ghidra_scripts directory.

Done!

## Sigga in action

Select any function (or place your cursor inside one) and press your assigned keybind. 

Sigga will immediately analyze the function, find the best possible signature (checking Direct, XRef, and Fallback tiers), and **automatically copy it to your clipboard**.

Check the Ghidra Console window for details on the generated signature quality and offset.

## Contributing/Bug reporting

I **highly** appreciate anyone that wants to contribute by fixing bugs or adding new functionality!

Feel free to open a pull request, but please make sure your changes/new code are properly documented and formatted :)

## Credits
- **lexika** - Original author and creator of Sigga.
- **[@Krixx1337](https://github.com/Krixx1337)** - Major architectural overhaul, adding the XRef fallback, sliding window search, and advanced stability analysis.
- **outercloudstudio** - Fixed a bug with the original wildcard placement.

## Known bugs/Issues

- None.
