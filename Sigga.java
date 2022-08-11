//Budget sigmaker for Ghidra (Version 1.1)
//@author lexika
//@category Functions
//@keybinding
//@menupath
//@toolbar

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSetViewAdapter;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.security.InvalidParameterException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

public class Sigga extends GhidraScript {
    /**
     * Helper class to convert a string signature to bytes + mask, also acts as a container for them
     */
    private static class ByteSignature {
        public ByteSignature(String signature) throws InvalidParameterException {
            parseSignature(signature);
        }

        /**
         * Parse a string signature (like "56 8B ? ? 06 FF 8B") to arrays representing the actual signature and a mask
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
     * Get the function of the currently selected address in the GUI
     *
     * @return The selected function, otherwise null
     */
    private Function getCurrentFunction() {
        // Not sure if this can happen
        if (currentLocation == null) {
            return null;
        }

        Address address = currentLocation.getAddress();
        if (address == null) {
            return null;
        }

        return currentProgram.getFunctionManager().getFunctionContaining(address);
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
     *
     * @param instructions The instructions to create a signature from
     * @param maxLength    The maximum length, in bytes
     * @return The built signature
     * @throws MemoryAccessException If the instructions are in non-accessible memory
     */
    private String buildSignatureFromInstructions(InstructionIterator instructions, int maxLength) throws MemoryAccessException {
        StringBuilder signature = new StringBuilder();

        int bytes = 0;
        for (Instruction instruction : instructions) {
            // It seems that instructions that contain addresses which may change at runtime
            // are always something else then "fallthrough", so we just do this.
            // TODO: Do this more properly, like https://github.com/nosoop/ghidra_scripts/blob/master/makesig.py#L41
            if (instruction.isFallthrough()) {
                for (byte b : instruction.getBytes()) {
                    // %02X = byte -> hex string
                    signature.append(String.format("%02X ", b));
                }
            } else {
                for (byte b : instruction.getBytes()) {
                    signature.append("? ");
                }
            }

            bytes++;
            if (bytes >= maxLength) {
                return signature.toString();
            }
        }

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
     * Create a relative signature for the function passed, null if none can be found
     * To achieve this, we iterate over all functions that call the function we are trying to make a signature for
     * Then we decompile them, find the call, try to sig the call itself
     *
     * @param function     The function to create a signature for
     * @param functionBody The function's body
     * @param instructions The function's instructions
     * @return The first unique relative signature found
     */
    private String createRelativeSignature(Function function, AddressSetView functionBody, InstructionIterator instructions) throws MemoryAccessException {
        // Prepare the decompiler
        DecompInterface decompInterface = new DecompInterface();
        decompInterface.openProgram(currentProgram);

        // Iterate all functions that call the function we are creating a signature for
        for (Function callingFunction : function.getCallingFunctions(monitor)) {
            // Decompile it
            DecompileResults decompileResults = decompInterface.decompileFunction(callingFunction, 1, monitor);

            // Iterate all Instructions in the function
            for (Iterator<PcodeOpAST> it = decompileResults.getHighFunction().getPcodeOps(); it.hasNext(); ) {
                PcodeOpAST instruction = it.next();

                // Is the current instruction a call?
                if (instruction.getMnemonic().equals("CALL")) {
                    // The address of the call instruction
                    Address source = instruction.getSeqnum().getTarget();
                    // The address of the function it's calling
                    Address target = instruction.getInput(0).getAddress();

                    // Is this calling the function we are trying to create a signature for?
                    if (target.equals(functionBody.getMinAddress())) {
                        AddressSetView callingFunctionBody = callingFunction.getBody();

                        // To make sure we only build a signature from the call address util function end, we need the size
                        int callingFunctionSize = (int) callingFunctionBody.getMaxAddress().subtract(source);

                        // Done!
                        return buildSignatureFromInstructions(currentProgram.getListing().getInstructions(source, true), callingFunctionSize);
                    }
                }
            }
        }

        // We could not find a function containing a siggable call to our target function
        return null;
    }

    /**
     * Create a signature for the function currently selected in the editor and output it
     *
     * @throws MemoryAccessException If the selected function is inside non-accessible memory
     */
    private void createSignature() throws MemoryAccessException {
        Function function = getCurrentFunction();

        // If we have no function selected, fail
        if (function == null) {
            printerr("Failed to create signature: No function selected");
            return;
        }

        AddressSetView functionBody = function.getBody();

        // Get instructions for current function
        InstructionIterator instructions = currentProgram.getListing().getInstructions(functionBody, true);

        // Generate signature for whole function
        String signature = buildSignatureFromInstructions(instructions, Integer.MAX_VALUE);

        // Try to find it once to make sure the first address found matches the one we generated it from
        // We know the signature is valid at this point, so no need to catch the InvalidParameterException
        if (!findAddressForSignature(signature).equals(functionBody.getMinAddress())) {
            // Function signature is not unique, make a relative signature instead
            println("Warning: Function is not big enough to create a unique signature. Generating relative signature instead...");

            signature = createRelativeSignature(function, functionBody, instructions);
            if (signature == null) {
                printerr("Failed to create signature: Cannot find unique function or relative signature");
                return;
            }
        }

        // Try to make the signature as small as possible while still being the first one found
        // Also strip trailing whitespaces and wildcards
        // TODO: Make this faster - Depending on the program's size and the size of the signature (function body), this could take quite some time
        signature = refineSignature(signature, functionBody.getMinAddress());

        // Selecting and copying the signature manually is a chore :)
        copySignatureToClipboard(signature);

        //                    (    Hopefully :)   )
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
     * Try to find the signature
     *
     * @param signature The signature to find
     * @return The first address the signature matches on
     * @throws InvalidParameterException If the signature has a invalid format
     */
    private Address findAddressForSignature(String signature) throws InvalidParameterException {
        // See class definition
        ByteSignature byteSignature = new ByteSignature(signature);

        // Try to find the signature
        return currentProgram.getMemory().findBytes(currentProgram.getMinAddress(), currentProgram.getMaxAddress(),
                byteSignature.getBytes(), byteSignature.getMask(), true, monitor);
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
        switch (askChoice("Sigga", "Choose a action to perform",
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
