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
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.util.exception.CancelledException;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

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

        List<List<String>> windows = buildInstructionWindows(function, MAX_INSTRUCTIONS_TO_SCAN, MIN_WINDOW_BYTES, MAX_WINDOW_BYTES);
        for (List<String> w : windows) {
            monitor.checkCancelled();
            if (!goodHead(w)) continue;                   // skip windows that start with "?" or are too weak up front
            String sig = String.join(" ", w);
            if (isSignatureUniqueInBinary(sig)) {
                copyToClipboard(sig);
                println("Found unique direct signature!");
                println("Signature: \"" + sig + "\"");
                return;
            }
        }

        println("Phase 1 failed. Proceeding to Phase 2: Signature by Cross-Reference (XRef).");
        tryXRefSignature(function);
    }

    private List<List<String>> buildInstructionWindows(Function f, int maxInsns, int minBytes, int maxBytes) throws MemoryAccessException {
        List<List<String>> perInsn = new LinkedList<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext() && perInsn.size() < maxInsns) {
            perInsn.add(instructionToTokens(it.next()));
        }
        List<List<String>> windows = new LinkedList<>();
        for (int i = 0; i < perInsn.size(); i++) {
            List<String> acc = new LinkedList<>();
            int total = 0;
            for (int j = i; j < perInsn.size(); j++) {
                List<String> add = perInsn.get(j);
                if (total + add.size() > maxBytes) break;
                acc.addAll(add);
                total += add.size();
                if (total >= minBytes) windows.add(new LinkedList<>(acc));
            }
        }
        return windows;
    }

    private boolean goodHead(List<String> w) {
        if (w == null || w.size() < 4) return false;
        // require first 4 tokens to be solid bytes
        for (int i = 0; i < 4; i++) {
            if ("?".equals(w.get(i))) return false;
        }
        return true;
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
    private List<String> instructionToTokens(Instruction insn) throws MemoryAccessException {
        byte[] bytes = insn.getBytes();
        String[] tok = new String[bytes.length];
        for (int i = 0; i < bytes.length; i++) tok[i] = String.format("%02X", bytes[i]);

        // 1) calls, jumps, returns, mask fully
        if (insn.getFlowType().isCall() || insn.getFlowType().isJump() || insn.getFlowType().isTerminal()) {
            Arrays.fill(tok, "?");
            return Arrays.asList(tok);
        }

        // 2) mask bytes covered by relocations in this instruction
        RelocationTable rt = currentProgram.getRelocationTable();
        Address insnStart = insn.getAddress();
        Address insnEnd = insnStart.add(bytes.length - 1);
        Iterator<Relocation> it = rt.getRelocations(new AddressSet(insnStart, insnEnd));
        while (it.hasNext()) {
            Relocation rel = it.next();
            Address ra = rel.getAddress();
            int off = (int) ra.subtract(insnStart);
            int len;
            try { len = rel.getLength(); } catch (Throwable t) { len = 4; }
            if (len <= 0) len = Math.min(4, Math.max(0, tok.length - off));
            for (int i = 0; i < len && off + i < tok.length && off + i >= 0; i++) tok[off + i] = "?";
        }

        // 3) mask trailing immediate scalars
        for (int op = 0; op < insn.getNumOperands(); op++) {
            if ((insn.getOperandType(op) & ghidra.program.model.lang.OperandType.SCALAR) != 0) {
                for (Object o : insn.getOpObjects(op)) {
                    if (o instanceof Scalar) {
                        int bits = ((Scalar) o).bitLength();
                        int n = Math.max(1, (bits + 7) / 8);
                        for (int i = 0; i < n && i < tok.length; i++) tok[tok.length - 1 - i] = "?";
                    }
                }
            }
        }

        // 4) mask RIP or EIP relative disp32 on memory refs
        boolean ripOrEipSeen = false, hasMemRef = false;
        for (int op = 0; op < insn.getNumOperands(); op++) {
            for (Object o : insn.getOpObjects(op)) {
                if (o instanceof Register) {
                    String rn = ((Register) o).getName().toUpperCase();
                    if (rn.equals("RIP") || rn.equals("EIP")) ripOrEipSeen = true;
                }
            }
            if (insn.getOperandReferences(op).length > 0) hasMemRef = true;
        }
        if (ripOrEipSeen && hasMemRef && tok.length >= 4) {
            for (int i = 0; i < 4; i++) tok[tok.length - 1 - i] = "?";
        }

        // 5) mask stack frame displacements like [rsp+imm] or [rbp+imm], unconditionally
        for (int op = 0; op < insn.getNumOperands(); op++) {
            Object[] objs = insn.getOpObjects(op);
            boolean baseIsSpBp = false;
            for (Object o : objs) {
                if (o instanceof Register) {
                    String rn = ((Register) o).getName().toUpperCase();
                    if (rn.equals("RSP") || rn.equals("ESP") || rn.equals("RBP") || rn.equals("EBP")) {
                        baseIsSpBp = true;
                    }
                }
            }
            if (baseIsSpBp) {
                // Mask up to 4 trailing bytes in the encoding to cover disp8 or disp32
                int n = Math.min(4, tok.length);
                for (int i = 0; i < n; i++) tok[tok.length - 1 - i] = "?";
                break; // one mem operand is enough
            }
        }

        return Arrays.asList(tok);
    }

    /**
     * Determines if an instruction is "stable" enough to be included in a signature.
     * Unstable instructions (jumps, calls, stack operations) are wildcarded.
     * This version is compatible with both x86 and x64 architectures.
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
                    // Check for all common stack and base pointer register names for x86/x64.
                    if (regName.equals("RSP") || regName.equals("ESP") ||  // Stack Pointers
                        regName.equals("RBP") || regName.equals("EBP")) {  // Base Pointers
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