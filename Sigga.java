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
    private static final int XREF_SIG_INSTRUCTIONS = 8; // How many instructions to use for an XRef signature.
    private static final int HEAD_CHECK_SPAN = 6;   // how many tokens to inspect from the start
    private static final int HEAD_MIN_SOLID  = 6;   // require at least this many non "?" in that span

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
        if (currentLocation == null) {
            printerr("No current location.");
            return;
        }
        Function function = getFunctionContaining(currentLocation.getAddress());
        if (function == null) {
            printerr("No function selected.");
            return;
        }
        if (function.isThunk()) { // skip import thunks and stubs
            println("Selected function is a thunk, trying XRef fallback.");
            tryXRefSignature(function);
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
        if (w == null || w.isEmpty()) return false;
        int span = Math.min(HEAD_CHECK_SPAN, w.size());
        int solid = 0;
        for (int i = 0; i < span; i++) {
            if (!"?".equals(w.get(i))) solid++;
        }
        return solid >= HEAD_MIN_SOLID;
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

            // Create a signature from the instructions leading up to the CALL, exclude the CALL itself
            List<Instruction> xrefInstructions = new LinkedList<>();
            Instruction current = refInstr.getPrevious(); // start before the CALL
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

        // 1) control flow, keep opcode, mask only relative offsets when applicable
        if (insn.getFlowType().isCall()) {
            // near rel32: E8 xx xx xx xx
            if (bytes.length == 5 && (bytes[0] & 0xFF) == 0xE8) {
                for (int i = 1; i < 5; i++) tok[i] = "?";
                return Arrays.asList(tok);
            }
            // other calls, often indirect, remain volatile
            Arrays.fill(tok, "?");
            return Arrays.asList(tok);
        }
        // x86 loop family and jecxz, keep opcode and mask rel8
        if (bytes.length == 2) {
            int b0 = bytes[0] & 0xFF;
            if (b0 == 0xE0 || b0 == 0xE1 || b0 == 0xE2 || b0 == 0xE3) { // LOOPNE, LOOPE, LOOP, JECXZ
                tok[1] = "?";
                return Arrays.asList(tok);
            }
        }
        if (insn.getFlowType().isJump()) {
            // short jmp: EB rel8
            if (bytes.length == 2 && (bytes[0] & 0xFF) == 0xEB) {
                tok[1] = "?";
                return Arrays.asList(tok);
            }
            // near jmp: E9 rel32
            if (bytes.length == 5 && (bytes[0] & 0xFF) == 0xE9) {
                for (int i = 1; i < 5; i++) tok[i] = "?";
                return Arrays.asList(tok);
            }
            Arrays.fill(tok, "?");
            return Arrays.asList(tok);
        }
        if (insn.getFlowType().isConditional()) {
            // short Jcc: 7x rel8
            if (bytes.length == 2 && (bytes[0] & 0xF0) == 0x70) {
                tok[1] = "?";
                return Arrays.asList(tok);
            }
            // near Jcc: 0F 8x rel32
            if (bytes.length >= 6 && (bytes[0] & 0xFF) == 0x0F && (bytes[1] & 0xF0) == 0x80) {
                for (int i = bytes.length - 4; i < bytes.length; i++) tok[i] = "?";
                return Arrays.asList(tok);
            }
            Arrays.fill(tok, "?");
            return Arrays.asList(tok);
        }
        // returns remain fully masked
        if (insn.getFlowType().isTerminal()) {
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

        // 5) mask stack frame displacements like [rsp+imm] or [rbp+imm], mask only the disp bytes
        for (int op = 0; op < insn.getNumOperands(); op++) {
            Object[] objs = insn.getOpObjects(op);

            boolean hasSpBp = false;
            int dispBytes = 0;        // 0 means no displacement detected
            boolean memOperand = false;

            for (Object o : objs) {
                if (o instanceof Register) {
                    String rn = ((Register) o).getName().toUpperCase();
                    if (rn.equals("RSP") || rn.equals("ESP") || rn.equals("RBP") || rn.equals("EBP")) {
                        hasSpBp = true;
                    }
                } else if (o instanceof Scalar) {
                    int bits = ((Scalar) o).bitLength();
                    if (bits <= 8) dispBytes = Math.max(dispBytes, 1);
                    else if (bits <= 32) dispBytes = Math.max(dispBytes, 4);
                }
            }

            // treat as memory if operand has refs, or is typed as ADDRESS
            int optype = insn.getOperandType(op);
            if (insn.getOperandReferences(op).length > 0 || (optype & OperandType.ADDRESS) != 0) {
                memOperand = true;
            }

            if (hasSpBp && memOperand) {
                if (dispBytes == 0) dispBytes = 1;  // typical [rsp+imm8] uses an 8-bit disp, keep opcode/ModRM/SIB
                for (int i = 0; i < dispBytes && i < tok.length; i++) {
                    tok[tok.length - 1 - i] = "?";  // mask only trailing disp bytes
                }
            }
        }

        // 6) extra safety for LEA, mask only the displacement at the end of the encoding
        if ("LEA".equalsIgnoreCase(insn.getMnemonicString())) {
            int dispBytes = 0;
            for (int op = 0; op < insn.getNumOperands(); op++) {
                for (Object o : insn.getOpObjects(op)) {
                    if (o instanceof Scalar) {
                        int bits = ((Scalar) o).bitLength();
                        if (bits <= 8) dispBytes = Math.max(dispBytes, 1);
                        else if (bits <= 32) dispBytes = Math.max(dispBytes, 4);
                    }
                }
            }
            if (dispBytes == 0) dispBytes = 1; // common LEA [rsp+imm8]
            for (int i = 0; i < dispBytes && i < tok.length; i++) {
                tok[tok.length - 1 - i] = "?"; // mask only trailing disp bytes
            }
        }

        return Arrays.asList(tok);
    }

    /**
     * Scans the entire program memory to check if a signature is unique.
     *
     * @param signature The signature to test.
     * @return True if exactly one match is found.
     */
    private boolean isSignatureUniqueInBinary(String signature) throws CancelledException {
        if (signature == null || signature.isEmpty()) return false;
        ByteSignature sig = new ByteSignature(signature);
        Memory mem = currentProgram.getMemory();
        int hits = 0;

        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isExecute()) continue;
            Address start = block.getStart();
            Address end = block.getEnd();
            Address cur = start;

            while (true) {
                monitor.checkCancelled();
                Address hit = mem.findBytes(cur, sig.getBytes(), sig.getMask(), true, monitor);
                if (hit == null || hit.compareTo(end) > 0) break;
                hits++;
                if (hits > 1) return false;
                Address next = hit.add(1);
                if (next.compareTo(end) > 0) break;
                cur = next;
            }
        }
        return hits == 1;
    }

    /**
     * Prompts the user for a signature and finds its location in memory.
     */
    private void findSignature() {
        try {
            String signature = askString("Find Signature", "Enter signature:");
            ByteSignature sig = new ByteSignature(signature);

            Memory mem = currentProgram.getMemory();
            for (MemoryBlock block : mem.getBlocks()) {
                if (!block.isExecute()) continue;

                Address start = block.getStart();
                Address end = block.getEnd();
                Address cur = start;

                while (true) {
                    monitor.checkCancelled();
                    Address hit = mem.findBytes(cur, sig.getBytes(), sig.getMask(), true, monitor);
                    if (hit == null || hit.compareTo(end) > 0) break;

                    println("Signature found at: " + hit);
                    goTo(hit);
                    return; // stop at first executable match
                }
            }

            println("Signature not found in executable blocks.");
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