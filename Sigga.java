// A massively improved sigmaker for Ghidra
// This version includes a fast "Sliding Window" algorithm and a powerful "XRef Fallback"
// to create reliable signatures for even the most complex, non-unique functions.
//@author lexika, Krixx1337
//@category Functions
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.lang.Register;
import ghidra.util.exception.CancelledException;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Arrays;

public class Sigga extends GhidraScript {

    // --- CONFIGURATION ---
    private static final int MAX_INSTRUCTIONS_TO_SCAN = 256;
    private static final int MIN_WINDOW_BYTES = 16;
    private static final int MAX_WINDOW_BYTES = 64;
    private static final int WINDOW_STEP_BYTES = 8;
    private static final int XREF_SIG_INSTRUCTIONS = 8; // How many instructions to use for an XRef signature.

    /**
     * Helper class to convert a string signature to bytes + mask.
     */
    private static class ByteSignature {
        private byte[] bytes;
        private byte[] mask;

        public ByteSignature(String signature) {
            parseSignature(signature);
        }

        /**
         * Parses a string signature (like "56 8B ? ? 06") into byte and mask arrays.
         *
         * @param signature The string-format signature to parse.
         * @throws IllegalArgumentException If the signature has an invalid format.
         */
        private void parseSignature(String signature) throws IllegalArgumentException {
            String cleanSignature = signature.replaceAll("\\s", "");
            if (cleanSignature.isEmpty()) {
                throw new IllegalArgumentException("Signature cannot be empty.");
            }

            List<Byte> byteList = new LinkedList<>();
            List<Byte> maskList = new LinkedList<>();

            for (int i = 0; i < cleanSignature.length();) {
                char character = cleanSignature.charAt(i);
                if (character == '?') {
                    byteList.add((byte) 0x00);
                    maskList.add((byte) 0x00);
                    i++;
                    continue;
                }

                try {
                    byte value = (byte) Integer.parseInt(cleanSignature.substring(i, i + 2), 16);
                    byteList.add(value);
                    maskList.add((byte) 0xFF);
                    i += 2;
                } catch (NumberFormatException | StringIndexOutOfBoundsException e) {
                    throw new IllegalArgumentException("Invalid hex character or wildcard in signature.", e);
                }
            }
            this.bytes = toByteArray(byteList);
            this.mask = toByteArray(maskList);
        }

        private byte[] toByteArray(List<Byte> list) {
            byte[] array = new byte[list.size()];
            for (int i = 0; i < list.size(); i++) {
                array[i] = list.get(i);
            }
            return array;
        }

        public byte[] getBytes() { return bytes; }
        public byte[] getMask() { return mask; }
    }

    /**
     * The script entry point.
     */
    @Override
    public void run() throws Exception {
        String action = askChoice("Sigga", "Choose an action:", Arrays.asList("Create Signature", "Find Signature"), "Create Signature");
        if ("Create Signature".equals(action)) {
            createSignature();
        } else if ("Find Signature".equals(action)) {
            findSignature();
        }
    }
    
    /**
     * Main function to create a signature for the function at the current cursor location.
     * Uses a two-phase approach: direct scan, then XRef fallback scan.
     */
    private void createSignature() throws MemoryAccessException, CancelledException {
        Function function = getFunctionContaining(currentLocation.getAddress());
        if (function == null) {
            printerr("No function selected.");
            return;
        }

        println("Phase 1: Scanning for a direct signature in: " + function.getName());
        
        List<String> featureVector = buildFeatureVector(function, MAX_INSTRUCTIONS_TO_SCAN);
        if (featureVector.size() < MIN_WINDOW_BYTES) {
            println("Function is too small for direct scan, proceeding to XRef scan.");
        } else {
            // Use a sliding window to find the first unique pattern within the function.
            for (int windowSize = MIN_WINDOW_BYTES; windowSize <= MAX_WINDOW_BYTES; windowSize += WINDOW_STEP_BYTES) {
                monitor.checkCancelled();
                monitor.setMessage(String.format("Sigga: Searching with window size %d...", windowSize));
                for (int offset = 0; offset <= featureVector.size() - windowSize; offset++) {
                    monitor.checkCancelled();
                    List<String> window = featureVector.subList(offset, offset + windowSize);
                    String signature = String.join(" ", window);
                    if (isSignatureUniqueInBinary(signature)) {
                        String finalOutput = String.format("Signature: \"%s\" (Offset: %d)", signature, offset);
                        copyToClipboard(signature);
                        println("Found unique direct signature!");
                        println(finalOutput + " - Signature text copied to clipboard.");
                        return;
                    }
                }
            }
        }
        
        // If Phase 1 fails, attempt to find a signature via a cross-reference.
        println("Phase 1 failed. Proceeding to Phase 2: Signature by Cross-Reference (XRef).");
        tryXRefSignature(function);
    }
    
    /**
     * Fallback method to find a signature for a function's CALLER.
     *
     * @param function The function that could not be signed directly.
     */
    private void tryXRefSignature(Function function) throws MemoryAccessException, CancelledException {
        Reference[] refs = getReferencesTo(function.getEntryPoint());
        for (Reference ref : refs) {
            monitor.checkCancelled();
            Address refAddr = ref.getFromAddress();
            Instruction refInstr = getInstructionAt(refAddr);
            
            MemoryBlock block = getMemoryBlock(refAddr);
            if (refInstr == null || !refInstr.getFlowType().isCall() || block == null || !block.isExecute()) {
                continue;
            }

            // Create a signature from the instructions leading up to the CALL.
            List<Instruction> xrefInstructions = new LinkedList<>();
            Instruction current = refInstr;
            for (int i = 0; i < XREF_SIG_INSTRUCTIONS && current != null; i++) {
                xrefInstructions.add(current);
                current = current.getPrevious();
            }
            Collections.reverse(xrefInstructions);
            
            String signature = buildFeatureString(xrefInstructions);
            if (isSignatureUniqueInBinary(signature)) {
                String finalOutput = String.format("Signature: \"%s\" (Found via XRef from %s)", signature, refAddr);
                copyToClipboard(signature);
                println("Found unique XRef signature!");
                println(finalOutput + " - This signature finds the CALLER, not the function itself.");
                return;
            }
        }
        printerr("Failed to find any unique signature for this function, even via XRefs.");
    }
    
    /**
     * Converts a large chunk of a function into a "feature vector" of byte tokens.
     *
     * @param function The function to analyze.
     * @param limit The maximum number of instructions to process.
     * @return A list of strings, where each string is a hex byte ("XX") or a wildcard ("?").
     */
    private List<String> buildFeatureVector(Function function, int limit) throws MemoryAccessException {
        List<String> tokens = new LinkedList<>();
        InstructionIterator iter = currentProgram.getListing().getInstructions(function.getBody(), true);
        while (iter.hasNext() && tokens.size() < (limit * 16)) { // Heuristic limit
            tokens.addAll(instructionToTokens(iter.next()));
        }
        return tokens;
    }
    
    /**
     * Converts a list of instructions into a single signature string.
     */
    private String buildFeatureString(List<Instruction> instructions) throws MemoryAccessException {
        List<String> tokens = new LinkedList<>();
        for (Instruction instruction : instructions) {
            tokens.addAll(instructionToTokens(instruction));
        }
        return String.join(" ", tokens);
    }

    /**
     * Converts a single instruction into a list of byte tokens.
     */
    private List<String> instructionToTokens(Instruction instruction) throws MemoryAccessException {
        List<String> tokens = new LinkedList<>();
        if (isInstructionStableForSignature(instruction)) {
            for (byte b : instruction.getBytes()) {
                tokens.add(String.format("%02X", b));
            }
        } else {
            for (int i = 0; i < instruction.getLength(); i++) {
                tokens.add("?");
            }
        }
        return tokens;
    }

    /**
     * Determines if an instruction is "stable" enough to be included in a signature.
     * Unstable instructions (jumps, calls, stack operations) are wildcarded.
     *
     * @param instruction The instruction to check.
     * @return True if the instruction is stable.
     */
    private boolean isInstructionStableForSignature(Instruction instruction) {
        if (instruction.getFlowType().isJump() || instruction.getFlowType().isCall()) {
            return false;
        }
        for (int i = 0; i < instruction.getNumOperands(); i++) {
            Object[] opObjects = instruction.getOpObjects(i);
            for (Object obj : opObjects) {
                if (obj instanceof Register) {
                    Register reg = (Register) obj;
                    String regName = reg.getName().toUpperCase();
                    if (regName.equals("RSP") || regName.equals("EBP")) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    /**
     * Scans the entire program memory to check if a signature is unique.
     *
     * @param signature The signature to test.
     * @return True if exactly one match is found.
     */
    private boolean isSignatureUniqueInBinary(String signature) throws CancelledException {
        if (signature.isEmpty()) return false;
        ByteSignature sig = new ByteSignature(signature);
        Memory mem = currentProgram.getMemory();
        Address firstMatch = mem.findBytes(currentProgram.getMinAddress(), sig.bytes, sig.mask, true, monitor);
        if (firstMatch == null) return false;
        Address secondMatch = mem.findBytes(firstMatch.add(1), sig.bytes, sig.mask, true, monitor);
        return (secondMatch == null);
    }
    
    /**
     * Prompts the user for a signature and finds its location in memory.
     */
    private void findSignature() {
        try {
            String signature = askString("Find Signature", "Enter signature:");
            ByteSignature sig = new ByteSignature(signature);
            Address found = currentProgram.getMemory().findBytes(currentProgram.getMinAddress(), sig.bytes, sig.mask, true, monitor);
            if (found == null) {
                println("Signature not found.");
            } else { 
                println("Signature found at: " + found);
                goTo(found);
            }
        } catch (Exception e) {
            printerr("Error: " + e.getMessage());
        }
    }

    /**
     * Copies a string to the system clipboard.
     *
     * @param text The text to copy.
     */
    private void copyToClipboard(String text) {
        try {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(new StringSelection(text), null);
        } catch (Exception e) {
            printerr("Warning: Could not copy to clipboard. " + e.getMessage());
        }
    }
}