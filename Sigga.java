//Budget sigmaker for Ghidra (Version 1.1)
//@author lexika, Narmjep
//@category Functions
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class Sigga extends GhidraScript {
    /**
     * Helper class to convert a string signature to bytes + mask, also acts as a
     * container for them
     */
    private static class ByteSignature {
        public ByteSignature(String signature) throws InvalidParameterException {
            parseSignature(signature);
        }

        /**
         * Parse a string signature (like "56 8B ? ? 06 FF 8B") two arrays representing
         * the actual signature and a mask
         * This is done, so that we can pass these two arrays directly into
         * currentProgram.getMemory().findBytes()
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

            final List<Byte> bytes = new LinkedList<>();
            final List<Byte> mask = new LinkedList<>();
            for (int i = 0; i < signature.length();) {
                // Do not convert wildcards
                if (signature.charAt(i) == '?') {
                    bytes.add((byte) 0);
                    mask.add((byte) 0);

                    i++;
                    continue;
                }

                try {
                    // Try to convert the hex string representation of the byte to the actual byte
                    bytes.add(Integer.decode("0x" + signature.substring(i, i + 2)).byteValue());
                } catch (NumberFormatException exception) {
                    throw new InvalidParameterException(exception.getMessage());
                }

                // Not a wildcard
                mask.add((byte) 1);

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
        if (currentLocation == null) {
            return null;
        }

        Address address = currentLocation.getAddress();
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
     * Given an iterator of instructions, build a string-signature by converting the
     * bytes into a hex format
     *
     * @param instructions The instructions to create a signature from
     * @return The built signature
     * @throws MemoryAccessException If the instructions are in non-accessible
     *                               memory
     */
    private String buildSignatureFromInstructions(InstructionIterator instructions) throws MemoryAccessException {
        StringBuilder signature = new StringBuilder();

        Address lastAddress = null;

        for (Instruction instruction : instructions) {
            Address instructionAddress = instruction.getAddress();

            // An unexpected jump in the instructions was detected, so we should go back and
            // add wildcards so that no bytes are missed causing the signature to not match
            if (lastAddress != null && !lastAddress.equals(instructionAddress)) {
                long offset = instructionAddress.getOffset() - lastAddress.getOffset();

                for (long i = 0; i < offset; i++) {
                    signature.append("? ");
                }
            }

            lastAddress = instructionAddress.add(instruction.getBytes().length);

            int index = 0;

            for (byte b : instruction.getBytes()) {
                int operandType = instruction.getOperandType(index);

                if ((operandType & OperandType.DYNAMIC) == OperandType.DYNAMIC) {
                    // Add a wildcard where the bytes may change
                    signature.append("? ");
                } else {
                    // %02X = byte -> hex string
                    signature.append(String.format("%02X ", b));
                }
            }
        }

        return signature.toString();
    }

    /**
     * Recursively refine the signature/make it smaller by removing the last byte
     * and trying to find it util it is not unique anymore
     * With any valid signature as an input, it will return the smallest possible
     * signature that is still guaranteed to be unique
     *
     * @param signature       The signature to refine
     * @param functionAddress The function address the signature points to
     * @return The refined signature
     */
    private String refineSignature(String signature, Address functionAddress) {
        // Strip trailing whitespaces and wildcards
        signature = cleanSignature(signature);

        // Remove last byte
        String newSignature = signature.substring(0, signature.length() - 2);

        // Try to find the new signature
        // We know the signature is valid and will at least be found once,
        // so no need to catch the InvalidParameterException or check for null
        Address foundAddress = findAddressForSignature(newSignature);

        // If the new signature is still unique, recursively refine it more
        if (foundAddress.equals(functionAddress)) {
            return refineSignature(newSignature, functionAddress);
        }

        // We cannot refine the signature anymore without making it not unique
        return signature;
    }

    /**
     * Create a signature for the function currently selected in the editor and
     * output it
     *
     * @throws MemoryAccessException If the selected function is inside
     *                               not-accessible memory
     */
    private void createSignature() throws MemoryAccessException {
        // Get currently selected function's body
        AddressSetView functionBody = getCurrentFunctionBody();

        // If we have no function selected, fail
        if (functionBody == null) {
            printerr("Failed to create signature: No function selected");
            return;
        }

        // Get instructions for current function
        InstructionIterator instructions = currentProgram.getListing().getInstructions(functionBody, true);

        // Generate signature for whole function
        String signature = buildSignatureFromInstructions(instructions);
        String originalSignature = signature;

        Address address = findAddressForSignature(signature);

        if (address == null) {
            printerr("Failed to create signature! Generated signature matched no function.");
            return;
        }

        // Try to find it once to make sure the first address found matches the one we
        // generated it from
        // We know the signature is valid at this point, so no need to catch the
        // InvalidParameterException
        if (!address.equals(functionBody.getMinAddress())) {
            // I don't see what other problem could cause this
            printerr(
                    "Failed to create signature: Function is (most likely) not big enough to create a unique signature. Matched "
                            + address.toString() + " instead.");
            return;
        }

        // Try to make the signature as small as possible while still being the first
        // one found
        // Also strip trailing whitespaces and wildcards
        // TODO: Make this faster - Depending on the program's size and the size of the
        // signature (function body) this could take quite some time
        signature = refineSignature(signature, functionBody.getMinAddress());

        // Selecting and copying the signature manually is a chore :)
        copySignatureToClipboard(signature);

        println(signature + " (Copied to clipboard)");
    }

    /**
     * Copy the generated signature to the clipboard for ease of use
     * 
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
     * Try to find the signature. Used when creating a signature
     *
     * @param signature The signature to find
     * @return The first address the signature matches on
     * @throws InvalidParameterException If the signature has a invalid format
     */
    private Address findAddressForSignature(String signature) throws InvalidParameterException {
        // See class definition
        ByteSignature byteSignature = new ByteSignature(signature);

        // Try to find the signature
        byte[] bytes = byteSignature.getBytes();
        byte[] mask = byteSignature.getMask();

        Address address = findBytesManual(currentProgram.getMinAddress(), currentProgram.getMaxAddress(),
                bytes, mask);

        return address;
    }

    /**
     * Find all addresses matching the signature. Used when searching for a signature
     * @param signature The signature to find
     * @return A list of addresses matching the signature
     * @throws InvalidParameterException
     */
    private List<Address> findAllAddressesForSignature(String signature) throws InvalidParameterException {
        // See class definition
        ByteSignature byteSignature = new ByteSignature(signature);

        // Try to find the signature
        byte[] bytes = byteSignature.getBytes();
        byte[] mask = byteSignature.getMask();

        List<Address> addresses = findAllBytesManual(currentProgram.getMinAddress(), currentProgram.getMaxAddress(),
                bytes, mask);

        return addresses;
    }

    /**
     * Verify if the signature matches the bytes at the given address.
     * @param address The address to verify the signature at
     * @param byteSignature The signature to verify
     * @return True if the signature matches the bytes at the address, false otherwise
     */
    private boolean verifySignatureMatch(Address address, ByteSignature byteSignature) {
        if (address == null) {
            println("No match found.");
            return true;
        }

        byte[] pattern = byteSignature.getBytes();
        byte[] mask = byteSignature.getMask();
        byte[] memory = new byte[pattern.length];
    
        try {
            currentProgram.getMemory().getBytes(address, memory);

            boolean isMatch = true;
    
            for (int i = 0; i < pattern.length; i++) {
                boolean matches = (mask[i] == 0) || (memory[i] == pattern[i]);
                String status = matches ? "OK" : "MISMATCH";
                if (!matches) {
                    isMatch = false;
                }
            }
            return isMatch;
        } catch (MemoryAccessException e) {
            println("Error reading memory at address " + address + ": " + e.getMessage());
            return false;
        }
    }

    /**
     * Finds the first address matching the signature
     * This function replaces the former simple call to memory.findBytes() with the signature.
     * This function uses memory.findBytes() to find an anchor in the pattern (no wildcards, so no mask is needed --> no false positives)
     * @param start Start address to search from
     * @param end End address to search to
     * @param pattern The byte pattern to search for
     * @param mask The mask to use for the search where 0 = wildcard, 1 = match
     * @return The first address matching the pattern
     */
    private Address findBytesManual(Address start, Address end, byte[] pattern, byte[] mask) {
        Memory memory = currentProgram.getMemory();
        Anchor anchor = extractAnchor(pattern, mask);
    
        if (anchor == null) {
            println("No anchor found in pattern.");
            return null;
        }
    
        Address cur = start;
        long totalRange = end.subtract(start);
        monitor.initialize(totalRange);
    
        while (cur.compareTo(end) <= 0) {
            if (monitor.isCancelled()) {
                println("Search cancelled.");
                return null;
            }
    
            try {
                Address anchorAddr = memory.findBytes(
                    cur, end, anchor.anchorBytes, null, true, monitor);
    
                if (anchorAddr == null) {
                    println("No anchor matches found.");
                    return null;
                }
    
                // backtrack to the beginning of the full pattern
                Address potentialStart = anchorAddr.subtract(anchor.offsetInPattern);
    
                // verify full match
                byte[] mem = new byte[pattern.length];
                memory.getBytes(potentialStart, mem);
    
                boolean match = true;
                for (int i = 0; i < pattern.length; i++) {
                    if (mask[i] != 0 && mem[i] != pattern[i]) {
                        match = false;
                        break;
                    }
                }
    
                if (match) {
                    return potentialStart;
                }
    
                // if no match, advance just after this anchor and keep going
                cur = anchorAddr.add(1);
            } catch (Exception e) {
                // skip bad memory or address issues
                cur = cur.add(1);
            }
    
            monitor.incrementProgress(1);
        }
    
        println("No optimized match found.");
        return null;
    }

    /**
     * A series of bytes that are part of a signature and contain no wildcards
     */
    private class Anchor {
        /**
         * The offset in the pattern where the anchor starts
         */
        int offsetInPattern;
        byte[] anchorBytes;
    }
    
    /**
     * Retrieves the first anchor in the pattern
     * @param pattern
     * @param mask
     * @return
     */
    private Anchor extractAnchor(byte[] pattern, byte[] mask) {
        int start = -1;
        int end = -1;
    
        for (int i = 0; i < mask.length; i++) {
            if (mask[i] != 0) {
                if (start == -1) start = i;
                end = i;
            } else if (start != -1) {
                break; // only take the first contiguous non-wildcard block
            }
        }
    
        if (start == -1) return null; // all wildcards? nothing to anchor
    
        byte[] anchorBytes = Arrays.copyOfRange(pattern, start, end + 1);
        Anchor anchor = new Anchor();
        anchor.offsetInPattern = start;
        anchor.anchorBytes = anchorBytes;
        return anchor;
    }

    /**
     * Same as {@link #findBytesManual} but returns all matches
     * @param start Start address to search from
     * @param end End address to search to
     * @param pattern The byte pattern to search for
     * @param mask The mask to use for the search where 0 = wildcard, 1 = match
     * @return A list of addresses matching the pattern
     */
    private List<Address> findAllBytesManual(Address start, Address end, byte[] pattern, byte[] mask) {
        Memory memory = currentProgram.getMemory();
        Anchor anchor = extractAnchor(pattern, mask);

        List<Address> results = new ArrayList<>();

        if (anchor == null) {
            println("No anchor found in pattern.");
            return results;
        }

        Address cur = start;
        long totalRange = end.subtract(start);
        monitor.initialize(totalRange);

        while (cur.compareTo(end) <= 0) {
            if (monitor.isCancelled()) {
                println("Search cancelled.");
                return results;
            }

            try {
                Address anchorAddr = memory.findBytes(
                    cur, end, anchor.anchorBytes, null, true, monitor);

                if (anchorAddr == null) {
                    break;
                }

                Address potentialStart = anchorAddr.subtract(anchor.offsetInPattern);

                // Check if the full pattern fits in memory range
                if (potentialStart.compareTo(start) < 0 || 
                    potentialStart.add(pattern.length).compareTo(end) > 0) {
                    cur = anchorAddr.add(1);
                    continue;
                }

                byte[] mem = new byte[pattern.length];
                memory.getBytes(potentialStart, mem);

                boolean match = true;
                for (int i = 0; i < pattern.length; i++) {
                    if (mask[i] != 0 && mem[i] != pattern[i]) {
                        match = false;
                        break;
                    }
                }

                if (match) {
                    results.add(potentialStart);
                }

                // Move past the current anchor to keep searching
                cur = anchorAddr.add(1);
            } catch (Exception e) {
                cur = cur.add(1); // On failure, advance to the next byte
            }

            monitor.incrementProgress(1);
        }

        println("Total matches found: " + results.size());
        return results;
    }
 

    /**
     * Finds and outputs the signature
     *
     * @param signature The signature to find and output
     */
    private void findSignature(String signature) {
        List<Address> addresses = null;
        try {
            addresses = findAllAddressesForSignature(signature);

            if (addresses.isEmpty()) {
                println("Signature not found");
                return;
            }

            int totalMatches = addresses.size();

            for (int i = 0; i < totalMatches; i++) {
                Address addr = addresses.get(i);
                println(" --------- Match " + (i + 1) + "/" + totalMatches + ": " + addr);
                if (!verifySignatureMatch(addr, new ByteSignature(signature))) {
                    /*
                     * This should never happen.
                     * If it does, findAllBytesManual is not working correctly,
                     * and findBytesManual probably isn't either 
                     */
                    println("Signature found, but not valid");
                } else {
                    if (!currentProgram.getFunctionManager().isInFunction(addr)) {
                        println("Warning: The address found is not inside a function");
                    }
                }
            }
        } catch (InvalidParameterException exception) {
            printerr("Failed to find signature: " + exception.getMessage());
        }

    }

    /**
     * The script entry point - This gets called when it's executed
     *
     * @throws Exception If anything in the script went seriously wrong
     */
    public void run() throws Exception {
        switch (askChoice("Sigga", "Choose a action to perform",
                Arrays.asList(
                        "Create signature",
                        "Find signature"),
                "Create signature")) {
            case "Create signature":
                createSignature();
                break;
            case "Find signature":
                findSignature(askString("Sigga", "Enter signature to find:", ""));
                break;
        }
    }
}