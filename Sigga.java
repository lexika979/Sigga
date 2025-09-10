// A massively improved sigmaker for Ghidra
// This version includes a fast "Sliding Window" algorithm and a powerful "XRef Fallback"
// to create reliable signatures for even the most complex, non-unique functions.
//@author lexika, Krixx1337, outercloudstudio
//@category Functions
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.security.InvalidParameterException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class Sigga extends GhidraScript {
    // Track if we're analyzing a Linux binary (user selected)
    private boolean isLinuxBinary = false;
    
    /**
     * Helper class to convert a string signature to bytes + mask, also acts as a container for them
     */
    private static class ByteSignature {
        public ByteSignature(String signature) throws InvalidParameterException {
            parseSignature(signature);
        }

        /**
         * Parse a string signature (like "56 8B ? ? 06 FF 8B") two arrays representing the actual signature and a mask
         * This is done, so that we can pass these two arrays directly into currentProgram.getMemory().findBytes()
         *
         * @param signature The string-format signature to parse/convert
         * @throws InvalidParameterException If the signature has an invalid format
         */
        private void parseSignature(String signature) throws InvalidParameterException {
            // Remove all whitespaces for easier parsing
            signature = signature.replaceAll(" ", "");

            if (signature.isEmpty()) {
                throw new InvalidParameterException("Signature cannot be empty");
            }
            
            // Ensure signature length is even (pairs of hex chars or single '?')
            // Count wildcards first
            int wildcardCount = signature.length() - signature.replace("?", "").length();
            int hexChars = signature.length() - wildcardCount;
            if (hexChars % 2 != 0) {
                throw new InvalidParameterException("Invalid signature format: odd number of hex characters");
            }

            final List<Byte> bytes = new LinkedList<>();
            final List<Byte> mask = new LinkedList<>();
            for (int i = 0; i < signature.length(); ) {
                // Do not convert wildcards
                if (signature.charAt(i) == '?') {
                    bytes.add((byte) 0);
                    mask.add((byte) 0);

                    i++;
                    continue;
                }

                try {
                    // Try to convert the hex string representation of the byte to the actual byte
                    String hexByte = signature.substring(i, Math.min(i + 2, signature.length()));
                    if (hexByte.length() < 2) {
                        throw new InvalidParameterException("Incomplete hex byte at position " + i);
                    }
                    bytes.add(Integer.decode("0x" + hexByte).byteValue());
                } catch (NumberFormatException exception) {
                    throw new InvalidParameterException("Invalid hex at position " + i + ": " + exception.getMessage());
                }

                // Not a wildcard - use 0xFF for full byte match
                mask.add((byte) 0xFF);

                i += 2;
            }

            // Lists -> Member arrays
            this.bytes = new byte[bytes.size()];
            this.mask = new byte[mask.size()];
            for (int i = 0; i < bytes.size(); i++) {
                this.bytes[i] = bytes.get(i);
                this.mask[i] = mask.get(i);
            }
        }

        public byte[] getBytes() {
            return bytes;
        }

        public byte[] getMask() {
            return mask;
        }

        private byte[] bytes;
        private byte[] mask;
    }

    /**
     * Get the function body of the currently selected function in the GUI
     *
     * @return The body of the selected function, otherwise null
     */
    private AddressSetView getCurrentFunctionBody() {
        FunctionManager functionManager = currentProgram.getFunctionManager();
        Address address = null;
        
        // Try multiple methods to get the current address
        if (currentLocation != null) {
            address = currentLocation.getAddress();
        }
        
        // Fallback to currentAddress if currentLocation didn't work
        if (address == null && currentAddress != null) {
            address = currentAddress;
        }
        
        // Final fallback to selection
        if (address == null && currentSelection != null && !currentSelection.isEmpty()) {
            address = currentSelection.getMinAddress();
        }
        
        if (address == null) {
            return null;
        }

        Function function = functionManager.getFunctionContaining(address);
        if (function == null) {
            return null;
        }

        return function.getBody();
    }

    /**
     * Remove useless whitespaces and trailing wildcards
     *
     * @param signature The signature to clean
     * @return The cleaned signature
     */
    private String cleanSignature(String signature) {
        // Remove trailing whitespace
        signature = signature.strip();

        if (signature.endsWith("?")) {
            // Use recursion to remove wildcards at end
            return cleanSignature(signature.substring(0, signature.length() - 1));
        }

        return signature;
    }

    /**
     * Given an iterator of instructions, build a string-signature by converting the bytes into a hex format
     * Enhanced to properly handle both Windows PE and Linux ELF binaries
     *
     * @param instructions The instructions to create a signature from
     * @return The built signature
     * @throws MemoryAccessException If the instructions are in non-accessible memory
     */
    private String buildSignatureFromInstructions(InstructionIterator instructions) throws MemoryAccessException {
        StringBuilder signature = new StringBuilder();
        int instructionCount = 0;

        for (Instruction instruction : instructions) {
            instructionCount++;
            boolean shouldWildcard = false;
            
            // Get instruction bytes
            byte[] bytes = instruction.getBytes();
            if (bytes == null || bytes.length == 0) {
                // Skip instructions with no bytes
                continue;
            }
            
            // Check if instruction contains references that need wildcarding
            if (!instruction.isFallthrough()) {
                // Non-fallthrough instructions typically contain addresses
                shouldWildcard = true;
            } else {
                // For Linux binaries, be more careful with wildcarding
                if (isLinuxBinary) {
                    String mnemonic = instruction.getMnemonicString().toLowerCase();
                    String instructionStr = instruction.toString().toLowerCase();
                    
                    // Only wildcard very specific relocation patterns
                    // Avoid wildcarding regular jumps and calls unless they're clearly external
                    if ((mnemonic.equals("call") && instructionStr.contains("@")) ||  // External calls
                        instructionStr.contains("@got") ||  // GOT references
                        instructionStr.contains("@plt") ||  // PLT references
                        (instructionStr.contains("rip+0x") && !mnemonic.startsWith("lea"))) {  // RIP-relative (but not LEA)
                        shouldWildcard = true;
                    }
                }
                
                // Check if instruction has external references
                Reference[] refs = instruction.getReferencesFrom();
                for (Reference ref : refs) {
                    if (ref.isExternalReference() || 
                        ref.getReferenceType() == RefType.DATA ||
                        ref.getReferenceType() == RefType.COMPUTED_CALL ||
                        ref.getReferenceType() == RefType.COMPUTED_JUMP) {
                        shouldWildcard = true;
                        break;
                    }
                }
                
                // Check for large immediate values that might be addresses
                // Only check for very large values that are likely addresses
                int numOperands = instruction.getNumOperands();
                for (int i = 0; i < numOperands; i++) {
                    Object[] opObjects = instruction.getOpObjects(i);
                    for (Object obj : opObjects) {
                        if (obj instanceof Scalar) {
                            Scalar scalar = (Scalar) obj;
                            // Only wildcard values that really look like addresses
                            // 0x400000 is typical base for many executables
                            if (scalar.getUnsignedValue() > 0x400000) {
                                shouldWildcard = true;
                                break;
                            }
                        }
                    }
                    if (shouldWildcard) break;
                }
            }
            
            // Write bytes or wildcards
            if (shouldWildcard) {
                for (byte b : bytes) {
                    signature.append("? ");
                }
            } else {
                for (byte b : bytes) {
                    signature.append(String.format("%02X ", b));
                }
            }
        }
        
        // Removed debug output

        return signature.toString();
    }

    /**
     * Recursively refine the signature/make it smaller by removing the last byte and trying to find it util it is not unique anymore
     * With any valid signature as an input, it will return the smallest possible signature that is still guaranteed to be unique
     *
     * @param signature       The signature to refine
     * @param functionAddress The function address the signature points to
     * @return The refined signature
     */
    private String refineSignature(String signature, Address functionAddress) {
        // Strip trailing whitespaces and wildcards
        signature = cleanSignature(signature);

        // Make sure we have at least a minimal signature (at least 2-3 bytes)
        if (signature.length() <= 8) {  // 2 bytes + spaces = "XX XX " = 6 chars minimum
            return signature;
        }

        // Remove last byte
        String newSignature = signature.substring(0, signature.length() - 2);

        // Try to find the new signature
        Address foundAddress = null;
        try {
            foundAddress = findAddressForSignature(newSignature);
        } catch (InvalidParameterException e) {
            // If the new signature is invalid, return the original
            return signature;
        }

        // If we couldn't find it or it's still unique, recursively refine it more
        if (foundAddress != null && foundAddress.equals(functionAddress)) {
            return refineSignature(newSignature, functionAddress);
        }

        // We cannot refine the signature anymore without making it not unique
        return signature;
    }

    /**
     * Create a signature for the function currently selected in the editor and output it
     *
     * @throws MemoryAccessException If the selected function is inside not-accessible memory
     */
    private void createSignature() throws MemoryAccessException {
        // Get currently selected function's body
        AddressSetView functionBody = getCurrentFunctionBody();

        // If we have no function selected, fail
        if (functionBody == null) {
            printerr("Failed to create signature: No function selected");
            printerr("Make sure your cursor is positioned within a function body");
            return;
        }

        // Get instructions for current function
        InstructionIterator instructions = currentProgram.getListing().getInstructions(functionBody, true);

        // Generate signature for whole function
        String signature = buildSignatureFromInstructions(instructions);
        
        if (signature.trim().isEmpty()) {
            printerr("Failed to create signature: No instructions found in function");
            return;
        }
        
        // Check if signature is all wildcards
        String sigNoSpaces = signature.replaceAll(" ", "");
        if (sigNoSpaces.matches("\\?+")) {
            printerr("Failed to create signature: Signature is all wildcards (no unique bytes)");
            printerr("This can happen with very small functions or if all bytes are relocatable");
            return;
        }

        // Removed debug output - script is working properly now

        // Try to find it once to make sure the first address found matches the one we generated it from
        Address foundAddress = null;
        
        // Try to find the signature
        try {
            foundAddress = findAddressForSignature(signature);
        } catch (InvalidParameterException e) {
            printerr("Failed to create signature: " + e.getMessage());
            return;
        }
        
        if (foundAddress == null) {
            printerr("Failed to create signature: Signature not found");
            printerr("This can happen if the function is too small or has no unique bytes");
            return;
        }
        
        if (!foundAddress.equals(functionBody.getMinAddress())) {
            printerr("Failed to create signature: Function is not big enough to create a unique signature");
            printerr("The signature matches a different location first");
            // Different location found first
            return;
        }

        // Try to make the signature as small as possible while still being the first one found
        // Also strip trailing whitespaces and wildcards
        signature = refineSignature(signature, functionBody.getMinAddress());

        // Selecting and copying the signature manually is a chore :)
        copySignatureToClipboard(signature);

        println(signature + " (Copied to clipboard)");
    }

    /**
     * Copy the generated signature to the clipboard for ease of use
     * @param signature The signature to copy to the clipboard
     */
    private void copySignatureToClipboard(String signature) {
        StringSelection selection = new StringSelection(signature);

        try {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(selection, selection);
        } catch (AWTError | IllegalStateException exception) {
            println("Warning: Failed to copy signature to clipboard: " + exception.getMessage());
        }
    }

    /**
     * Try to find the signature
     *
     * @param signature The signature to find
     * @return The first address the signature matches on
     * @throws InvalidParameterException If the signature has a invalid format
     */
    private Address findAddressForSignature(String signature) throws InvalidParameterException {
        // See class definition
        ByteSignature byteSignature = new ByteSignature(signature);
        
        byte[] searchBytes = byteSignature.getBytes();
        byte[] searchMask = byteSignature.getMask();

        // Try to find the signature - first in executable blocks only
        Address result = null;
        
        // Try searching in executable memory blocks first (more efficient and correct)
        AddressSetView memoryBlocks = currentProgram.getMemory().getExecuteSet();
        if (memoryBlocks != null && !memoryBlocks.isEmpty()) {
            for (AddressRange range : memoryBlocks) {
                result = currentProgram.getMemory().findBytes(range.getMinAddress(), range.getMaxAddress(),
                        searchBytes, searchMask, true, monitor);
                if (result != null) {
                    break;
                }
            }
        }
        
        // If not found in executable blocks, try entire memory as fallback
        if (result == null) {
            result = currentProgram.getMemory().findBytes(currentProgram.getMinAddress(), currentProgram.getMaxAddress(),
                    searchBytes, searchMask, true, monitor);
        }
        
        return result;
    }

    /**
     * Finds and outputs the signature
     *
     * @param signature The signature to find and output
     */
    private void findSignature(String signature) {
        Address address = null;
        try {
            address = findAddressForSignature(signature);
        } catch (InvalidParameterException exception) {
            printerr("Failed to find signature: " + exception.getMessage());
        }

        if (address == null) {
            println("Signature not found");
            return;
        }

        if (!currentProgram.getFunctionManager().isInFunction(address)) {
            println("Warning: The address found is not inside a function");
        }

        println("Found signature at: " + address);
    }

    /**
     * The script entry point - This gets called when it's executed
     *
     * @throws Exception If anything in the script went seriously wrong
     */
    public void run() throws Exception {
        // First ask what type of binary they're analyzing
        String binaryType = askChoice("Sigga - Binary Type", 
                "Select the type of binary you are analyzing:\n\n" +
                "Windows: Standard PE files with direct addressing\n" +
                "Linux: ELF files with PIC/PIE (position-independent code)",
                Arrays.asList(
                        "Windows (PE)",
                        "Linux (ELF)"
                ), "Windows (PE)");
        
        isLinuxBinary = binaryType.equals("Linux (ELF)");
        
        // Print selected mode
        println("Sigga v1.2 - Mode: " + binaryType);
        if (isLinuxBinary) {
            println("Using enhanced wildcarding for PIC/PIE code");
        }
        
        // Then ask what action to perform
        switch (askChoice("Sigga", "Choose an action to perform",
                Arrays.asList(
                        "Create signature",
                        "Find signature"
                ), "Create signature")) {
            case "Create signature":
                createSignature();
                break;
            case "Find signature":
                findSignature(askString("Sigga", "Enter signature to find:", ""));
                break;
        }
    }
}
