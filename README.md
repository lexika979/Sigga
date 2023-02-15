# Sigga - sigmaker for Ghidra
*The name "Sigga" is a mix of the german word "Digga" (roughly translates to "brother"), and "Signature"*

Sigga is a minimal Ghidra script to create and find function signatures. It is well documented and easily maintainable.

## Features
It contains the core functionality of [the IDA Pro plugin equivalent](https://github.com/ajkhoury/SigMaker-x64) and some extras for the user's convenience.

- Create and find function signatures
- Signatures will automatically be copied to the clipboard once created
- Always creates the smallest possible signature

## Installation
To install Sigga, simply [download the latest release](https://github.com/lexika979/Sigga/releases) and put *Sigga.java* inside C:/Users/(your username)/ghidra_scripts. If the folder does not exist yet, create it first. - That's it!

I highly recommend binding Sigga to a shortcut to save yourself a lot of clicks. You can do so like this:

1) Open Ghidra and the Script manager:

![](https://i.imgur.com/usOQWPh.png)

2) Open the "Functions" folder:

![](https://i.imgur.com/sIxclgU.png)

3) Right click "Sigga" and assign a keybind (I recommend *Ctrl-Alt-S*):

![](https://i.imgur.com/N7kSe4F.png)

Troubleshooting: In case Sigga does not show up in the list, try to create a new script through the UI and immediately delete it again. That should force Ghidra to acknowledge the ghidra_scrits directory.

Done!

## Sigga in action

Select any function and press your assigned keybind, and Sigga's UI should pop up:

![](https://i.imgur.com/ewKOjLS.png)

![](https://i.imgur.com/mVA2oPr.png)

![](https://i.imgur.com/HfhQFxi.png)

## Contributing/Bug reporting

I **highly** appreciate anyone that wants to contribute by fixing bugs or adding new functionality!

Feel free to open a pull request, but please make sure your changes/new code are properly documented and formatted :)

## Known bugs/Issues

- Currently, the way I am placing wildcards is suboptimal. It may wildcard more instructions then actually needed.
- Sometimes it can't find specific signatures. This seems to be a bug in ghidra.
