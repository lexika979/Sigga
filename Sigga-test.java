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
    private static final int HEAD_MIN_SOLID  = 1;   // require at least this many non "?" in that span

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
     * Helper class to store a window with its starting instruction address.
     */
    private static class WindowWithOffset {
        private List<String> window;
        private Address startAddress;

        public WindowWithOffset(List<String> window, Address startAddress) {
            this.window = window;
            this.startAddress = startAddress;
        }

        public List<String> getWindow() { return window; }
        public Address getStartAddress() { return startAddress; }
    }

    /**
     * Helper class to store scan results and debug information.
     */
    private static class ScanResult {
        boolean success;
        int totalWindows;
        int windowsPassedHeadCheck;
        int windowsTestedForUniqueness;
        List<String> sampleRejectedWindows;
        List<String> testedSignatures;

        public ScanResult(boolean success, int totalWindows, int windowsPassedHeadCheck, 
                         int windowsTestedForUniqueness, List<String> sampleRejectedWindows, List<String> testedSignatures) {
            this.success = success;
            this.totalWindows = totalWindows;
            this.windowsPassedHeadCheck = windowsPassedHeadCheck;
            this.windowsTestedForUniqueness = windowsTestedForUniqueness;
            this.sampleRejectedWindows = sampleRejectedWindows;
            this.testedSignatures = testedSignatures;
        }
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

        ScanResult result = tryDirectSignatureWithStrictness(function, HEAD_MIN_SOLID);
        if (result.success) {
            return;
        }

        // Phase 1 failed - show interactive prompt
        String choice = askChoice("Phase 1 Failed", 
            "Direct signature scan failed. What would you like to do?",
            Arrays.asList("Try with lower strictness", "Proceed to XRef fallback", "Show debug information"),
            "Proceed to XRef fallback");

        if ("Try with lower strictness".equals(choice)) {
            int lowerStrictness = Math.max(1, HEAD_MIN_SOLID - 1);
            println("Retrying with lower strictness (HEAD_MIN_SOLID: " + lowerStrictness + " instead of " + HEAD_MIN_SOLID + ")...");
            ScanResult retryResult = tryDirectSignatureWithStrictness(function, lowerStrictness);
            if (retryResult.success) {
                return;
            }
            println("Retry with lower strictness also failed. Proceeding to XRef fallback.");
            tryXRefSignature(function);
        } else if ("Show debug information".equals(choice)) {
            showDebugInformation(result);
            String afterDebug = askChoice("Debug Info Shown", 
                "What would you like to do now?",
                Arrays.asList("Try with lower strictness", "Proceed to XRef fallback"),
                "Proceed to XRef fallback");
            if ("Try with lower strictness".equals(afterDebug)) {
                int lowerStrictness = Math.max(1, HEAD_MIN_SOLID - 1);
                println("Retrying with lower strictness (HEAD_MIN_SOLID: " + lowerStrictness + " instead of " + HEAD_MIN_SOLID + ")...");
                ScanResult retryResult = tryDirectSignatureWithStrictness(function, lowerStrictness);
                if (retryResult.success) {
                    return;
                }
                println("Retry with lower strictness also failed. Proceeding to XRef fallback.");
            }
            tryXRefSignature(function);
        } else {
            println("Proceeding to Phase 2: Signature by Cross-Reference (XRef).");
            tryXRefSignature(function);
        }
    }

    /**
     * Attempts to find a direct signature with configurable strictness.
     *
     * @param function The function to scan
     * @param headMinSolid The minimum number of solid bytes required in the head check
     * @return ScanResult containing success status and debug information
     */
    private ScanResult tryDirectSignatureWithStrictness(Function function, int headMinSolid) 
            throws MemoryAccessException, CancelledException {
        List<WindowWithOffset> windows = buildInstructionWindows(function, MAX_INSTRUCTIONS_TO_SCAN, MIN_WINDOW_BYTES, MAX_WINDOW_BYTES);
        Address functionStart = function.getEntryPoint();
        
        int totalWindows = windows.size();
        int windowsPassedHeadCheck = 0;
        int windowsTestedForUniqueness = 0;
        List<String> sampleRejectedWindows = new LinkedList<>();
        List<String> testedSignatures = new LinkedList<>();
        final int MAX_SAMPLE_WINDOWS = 5;
        final int MAX_TESTED_SIGNATURES = 5;

        for (WindowWithOffset windowWithOffset : windows) {
            monitor.checkCancelled();
            List<String> w = windowWithOffset.getWindow();
            
            if (!goodHead(w, headMinSolid)) {
                if (sampleRejectedWindows.size() < MAX_SAMPLE_WINDOWS) {
                    String sample = String.join(" ", w.subList(0, Math.min(20, w.size())));
                    sampleRejectedWindows.add(sample + (w.size() > 20 ? "..." : ""));
                }
                // Debug: show why longer windows are rejected
                if (w.size() >= 28 && windowWithOffset.getStartAddress().equals(functionStart)) {
                    int span = Math.min(HEAD_CHECK_SPAN, w.size());
                    int solid = 0;
                    for (int i = 0; i < span; i++) {
                        if (!"?".equals(w.get(i))) solid++;
                    }
                    println("DEBUG: Rejected window with " + w.size() + " tokens - head check: " + solid + " solid out of " + span + " (need " + headMinSolid + ")");
                }
                continue;
            }
            
            windowsPassedHeadCheck++;
            String sig = String.join(" ", w);
            windowsTestedForUniqueness++;
            
            if (testedSignatures.size() < MAX_TESTED_SIGNATURES) {
                String sigSample = sig.length() > 80 ? sig.substring(0, 80) + "..." : sig;
                testedSignatures.add(sigSample);
            }
            
            // Debug: show first few signatures being tested, and also show the longest window
            if (windowsTestedForUniqueness <= 3) {
                println("DEBUG: Testing signature #" + windowsTestedForUniqueness + " (" + w.size() + " tokens): " + 
                       (sig.length() > 120 ? sig.substring(0, 120) + "..." : sig));
            }
            
            // Also show the longest window that starts from the function beginning
            if (windowWithOffset.getStartAddress().equals(functionStart) && w.size() > 30) {
                println("DEBUG: Long window from function start: " + w.size() + " tokens, signature: " + 
                       (sig.length() > 150 ? sig.substring(0, 150) + "..." : sig));
            }
            
            if (isSignatureUniqueInBinary(sig)) {
                long offset = windowWithOffset.getStartAddress().subtract(functionStart);
                String finalOutput = String.format("Signature: \"%s\" (Offset: %d)", sig, offset);
                copyToClipboard(sig);
                println("Found unique direct signature!");
                println(finalOutput + " - Signature text copied to clipboard.");
                return new ScanResult(true, totalWindows, windowsPassedHeadCheck, windowsTestedForUniqueness, null, null);
            }
        }

        return new ScanResult(false, totalWindows, windowsPassedHeadCheck, windowsTestedForUniqueness, sampleRejectedWindows, testedSignatures);
    }

    /**
     * Displays debug information about why Phase 1 failed.
     */
    private void showDebugInformation(ScanResult result) {
        println("=== Debug Information ===");
        println("Total windows generated: " + result.totalWindows);
        println("Windows passing head check (HEAD_MIN_SOLID=" + HEAD_MIN_SOLID + "): " + result.windowsPassedHeadCheck);
        println("Windows tested for uniqueness: " + result.windowsTestedForUniqueness);
        
        if (result.windowsPassedHeadCheck == 0) {
            println("\nReason: No windows passed the head check (too many wildcards at the start).");
            println("All windows were rejected because they didn't have enough solid bytes in the first " + HEAD_CHECK_SPAN + " tokens.");
            if (result.sampleRejectedWindows != null && !result.sampleRejectedWindows.isEmpty()) {
                println("\nSample rejected windows (first " + result.sampleRejectedWindows.size() + "):");
                for (String sample : result.sampleRejectedWindows) {
                    println("  " + sample);
                }
            }
        } else if (result.windowsTestedForUniqueness > 0) {
            println("\nReason: All tested windows were not unique (found multiple matches in the binary).");
            println("This function likely has very common patterns that appear in multiple places.");
            if (result.testedSignatures != null && !result.testedSignatures.isEmpty()) {
                println("\nSignatures that were tested (passed head check but failed uniqueness):");
                for (String sig : result.testedSignatures) {
                    println("  " + sig);
                }
            }
        }
        println("========================");
    }

    private List<WindowWithOffset> buildInstructionWindows(Function f, int maxInsns, int minBytes, int maxBytes) throws MemoryAccessException {
        List<List<String>> perInsn = new LinkedList<>();
        List<Address> insnAddresses = new LinkedList<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
        int instructionCount = 0;
        while (it.hasNext() && perInsn.size() < maxInsns) {
            Instruction insn = it.next();
            perInsn.add(instructionToTokens(insn));
            insnAddresses.add(insn.getAddress());
            instructionCount++;
        }
        println("DEBUG: buildInstructionWindows - Processed " + instructionCount + " instructions, generated " + perInsn.size() + " token lists");
        // Debug: show tokenization of each instruction
        for (int i = 0; i < Math.min(6, perInsn.size()); i++) {
            List<String> tokens = perInsn.get(i);
            String tokenStr = String.join(" ", tokens);
            println("DEBUG: Instruction " + i + " at " + insnAddresses.get(i) + ": " + tokens.size() + " tokens -> " + 
                   (tokenStr.length() > 50 ? tokenStr.substring(0, 50) + "..." : tokenStr));
        }
        
        List<WindowWithOffset> windows = new LinkedList<>();
        for (int i = 0; i < perInsn.size(); i++) {
            List<String> acc = new LinkedList<>();
            int total = 0;
            Address startAddr = insnAddresses.get(i);
            int instructionsInWindow = 0;
            for (int j = i; j < perInsn.size(); j++) {
                List<String> add = perInsn.get(j);
                if (total + add.size() > maxBytes) {
                    if (i == 0) {
                        println("DEBUG: buildInstructionWindows - Window starting at instruction " + i + " stopped at instruction " + j + 
                               " (would exceed maxBytes " + maxBytes + ", current total: " + total + ", next instruction size: " + add.size() + ")");
                    }
                    break;
                }
                acc.addAll(add);
                total += add.size();
                instructionsInWindow++;
                if (total >= minBytes) {
                    windows.add(new WindowWithOffset(new LinkedList<>(acc), startAddr));
                    if (i == 0) {
                        if (windows.size() <= 3) {
                            println("DEBUG: buildInstructionWindows - Window #" + windows.size() + " starting at instruction " + i + 
                                   ": " + instructionsInWindow + " instructions, " + total + " bytes, starts at " + startAddr);
                        } else if (windows.size() == 4) {
                            // Show the 4th window (likely the final one with all instructions)
                            println("DEBUG: buildInstructionWindows - Window #4 starting at instruction " + i + 
                                   ": " + instructionsInWindow + " instructions, " + total + " bytes, starts at " + startAddr);
                            String sample = String.join(" ", acc.subList(0, Math.min(30, acc.size())));
                            println("DEBUG: buildInstructionWindows - Window #4 sample: " + sample + (acc.size() > 30 ? "..." : ""));
                        }
                    }
                }
            }
        }
        println("DEBUG: buildInstructionWindows - Generated " + windows.size() + " total windows");
        return windows;
    }

    private boolean goodHead(List<String> w, int minSolid) {
        if (w == null || w.isEmpty()) return false;
        int span = Math.min(HEAD_CHECK_SPAN, w.size());
        int solid = 0;
        for (int i = 0; i < span; i++) {
            if (!"?".equals(w.get(i))) solid++;
        }
        return solid >= minSolid;
    }

    private boolean goodHead(List<String> w) {
        return goodHead(w, HEAD_MIN_SOLID);
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

            // Create a signature starting from the CALL instruction itself, then include instructions after it
            List<Instruction> xrefInstructions = new LinkedList<>();
            Instruction current = refInstr; // start at the CALL
            for (int i = 0; i < XREF_SIG_INSTRUCTIONS && current != null; i++) {
                xrefInstructions.add(current);
                current = current.getNext();
            }
            
            String signature = buildFeatureString(xrefInstructions);
            if (isSignatureUniqueInBinary(signature)) {
                String finalOutput = String.format("Signature: \"%s\" (Found via XRef from %s)", signature, refAddr);
                copyToClipboard(signature);
                println("Found unique XRef signature!");
                println(finalOutput + " - This signature points directly to the call site.");
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
            // near Jcc: 0F 8x rel32 (standard encoding is exactly 6 bytes: 0F 8x + 4-byte offset)
            if (bytes.length == 6 && (bytes[0] & 0xFF) == 0x0F && (bytes[1] & 0xF0) == 0x80) {
                for (int i = 2; i < 6; i++) tok[i] = "?";
                return Arrays.asList(tok);
            }
            Arrays.fill(tok, "?");
            return Arrays.asList(tok);
        }
        // returns: keep opcode, mask operands if any
        if (insn.getFlowType().isTerminal()) {
            // RET (C3) and RET imm16 (C2 imm16) - keep opcode, mask operands
            if (bytes.length == 1 && (bytes[0] & 0xFF) == 0xC3) {
                // RET - single byte, keep as is
                return Arrays.asList(tok);
            }
            if (bytes.length == 3 && (bytes[0] & 0xFF) == 0xC2) {
                // RET imm16 - keep opcode, mask the 2-byte immediate
                tok[1] = "?";
                tok[2] = "?";
                return Arrays.asList(tok);
            }
            // Other terminal instructions (IRET, etc.) - fully mask for safety
            Arrays.fill(tok, "?");
            return Arrays.asList(tok);
        }

        // 2) mask bytes covered by relocations in this instruction
        RelocationTable rt = currentProgram.getRelocationTable();
        Address insnStart = insn.getAddress();
        Address insnEnd = insnStart.add(bytes.length - 1);
        Iterator<Relocation> it = rt.getRelocations(new AddressSet(insnStart, insnEnd));
        int defaultPointerSize = currentProgram.getDefaultPointerSize();
        ghidra.program.model.symbol.SymbolTable symbolTable = currentProgram.getSymbolTable();
        
        int relocationCount = 0;
        while (it.hasNext()) {
            relocationCount++;
            Relocation rel = it.next();
            Address ra = rel.getAddress();
            int off = (int) ra.subtract(insnStart);
            int len;
            try {
                len = rel.getLength();
            } catch (Throwable t) {
                printerr("Failed to get relocation length at " + ra + ": " + t);
                len = defaultPointerSize;
            }
            if (len <= 0) len = Math.min(defaultPointerSize, Math.max(0, tok.length - off));
            
            // First, mask at the relocation address (direct approach)
            for (int i = 0; i < len && off + i < tok.length; i++) tok[off + i] = "?";
            
            // Also try to find matching scalar operands (more robust approach)
            try {
                String symbolName = rel.getSymbolName();
                if (symbolName != null) {
                    List<ghidra.program.model.symbol.Symbol> symbols = symbolTable.getLabelOrFunctionSymbols(symbolName, null);
                    if (symbols.size() == 1) {
                        ghidra.program.model.symbol.Symbol symbol = symbols.get(0);
                        Address symbolAddr = symbol.getAddress();
                        if (symbolAddr.getAddressSpace().getAddressableUnitSize() == 1) {
                            long symbolValue = symbolAddr.getOffset();
                            
                            // Search operands for scalar matching this address value
                            for (int opIndex = 0; opIndex < insn.getNumOperands(); opIndex++) {
                                Scalar scalar = getScalarOperand(insn.getDefaultOperandRepresentationList(opIndex));
                                if (scalar != null && scalar.getUnsignedValue() == symbolValue) {
                                    // Found matching scalar operand, mask its bytes
                                    maskScalarInInstruction(insn, opIndex, scalar, tok, bytes);
                                    break;
                                }
                            }
                        }
                    }
                }
            } catch (Exception e) {
                // If symbol lookup fails, continue with direct masking
            }
        }
        if (relocationCount > 0) {
            println("DEBUG: Found " + relocationCount + " relocations at " + insnStart);
        }

        // 2b) mask addresses in operands that reference external symbols or data sections
        println("DEBUG: Section 2b - checking operand references");
        for (int op = 0; op < insn.getNumOperands(); op++) {
            Reference[] refs = insn.getOperandReferences(op);
            int optype = insn.getOperandType(op);
            println("DEBUG: Operand " + op + " - refs=" + refs.length + ", optype=0x" + Integer.toHexString(optype) + 
                   " (ADDRESS=" + ((optype & OperandType.ADDRESS) != 0) + ", DATA=" + ((optype & OperandType.DATA) != 0) + ")");
            
            // First, check if there's already a relocation for this operand (Section 2 already handled it)
            boolean hasRelocation = false;
            try {
                Iterator<Relocation> relIt = rt.getRelocations(new AddressSet(insnStart, insnEnd));
                while (relIt.hasNext()) {
                    Relocation rel = relIt.next();
                    // Check if relocation is in the operand's address range
                    Address relAddr = rel.getAddress();
                    if (relAddr.compareTo(insnStart) >= 0 && relAddr.compareTo(insnEnd) <= 0) {
                        hasRelocation = true;
                        println("DEBUG: Operand " + op + " already has relocation at " + relAddr + ", skipping (Section 2 handled it)");
                        break;
                    }
                }
            } catch (Exception e) {
                // Continue if relocation check fails
            }
            
            if (hasRelocation) {
                continue; // Skip this operand, relocation already masked
            }
            
            boolean shouldMask = false;
            Address refAddr = null;
            long encodedAddrValue = 0; // The encoded address/displacement in instruction bytes
            
            // Check operand references first
            for (Reference ref : refs) {
                refAddr = ref.getToAddress();
                println("DEBUG: Operand " + op + " has reference to " + refAddr);
                
                // Check if reference is to external symbol
                try {
                    ghidra.program.model.symbol.Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(refAddr);
                    if (symbol != null) {
                        println("DEBUG: Reference points to symbol " + symbol.getName() + ", external=" + symbol.isExternal());
                        if (symbol.isExternal()) {
                            shouldMask = true;
                            println("DEBUG: Should mask (external symbol)");
                            break;
                        }
                    }
                } catch (Exception e) {
                    println("DEBUG: Failed to get symbol: " + e.getMessage());
                }
                
                // Check if reference points to a data section (non-executable)
                if (!shouldMask) {
                    MemoryBlock block = getMemoryBlock(refAddr);
                    if (block != null) {
                        println("DEBUG: Reference points to block " + block.getName() + ", executable=" + block.isExecute());
                        if (!block.isExecute()) {
                            shouldMask = true;
                            println("DEBUG: Should mask (data section)");
                            break;
                        }
                    } else {
                        println("DEBUG: Reference has no memory block");
                    }
                }
            }
            
            // If we should mask, extract the displacement/address from the operand
            if (shouldMask) {
                println("DEBUG: Section 2b - extracting displacement/address from operand " + op);
                
                // Try to extract displacement from operand objects
                Object[] opObjects = insn.getOpObjects(op);
                for (Object obj : opObjects) {
                    if (obj instanceof Scalar) {
                        Scalar scalar = (Scalar) obj;
                        long scalarValue = scalar.getUnsignedValue();
                        int scalarSize = Math.max(1, (scalar.bitLength() + 7) / 8);
                        
                        // For x86-64, displacements are typically 32-bit
                        // Only consider scalars that are 4 bytes (32-bit) or larger
                        // Also skip small values (< 0x10000) that are likely immediates, not addresses
                        if (scalarSize >= 4 && scalarSize <= 8 && scalarValue >= 0x10000) {
                            // Check if this scalar value appears in the instruction bytes
                            // This is the encoded displacement/address
                            encodedAddrValue = scalarValue;
                            println("DEBUG: Found scalar displacement 0x" + Long.toHexString(encodedAddrValue) + " (size=" + scalarSize + ")");
                            break;
                        } else if (scalarSize >= 4 && scalarSize <= 8 && scalarValue < 0x10000) {
                            println("DEBUG: Skipping scalar displacement 0x" + Long.toHexString(scalarValue) + " (too small, likely immediate)");
                        }
                    }
                }
                
                // If no scalar found, try to extract from operand representation
                if (encodedAddrValue == 0) {
                    try {
                        Scalar scalar = getScalarOperand(insn.getDefaultOperandRepresentationList(op));
                        if (scalar != null) {
                            long scalarValue = scalar.getUnsignedValue();
                            int scalarSize = Math.max(1, (scalar.bitLength() + 7) / 8);
                            // Skip small values (< 0x10000) that are likely immediates, not addresses
                            if (scalarSize >= 4 && scalarSize <= 8 && scalarValue >= 0x10000) {
                                encodedAddrValue = scalarValue;
                                println("DEBUG: Found scalar from representation 0x" + Long.toHexString(encodedAddrValue) + " (size=" + scalarSize + ")");
                            } else if (scalarSize >= 4 && scalarSize <= 8 && scalarValue < 0x10000) {
                                println("DEBUG: Skipping representation scalar 0x" + Long.toHexString(scalarValue) + " (too small, likely immediate)");
                            }
                        }
                    } catch (Exception e) {
                        // Skip if extraction fails
                    }
                }
                
                // If still no encoded address found, try to find it by searching instruction bytes
                // for values that could be the encoded address (RIP-relative or absolute)
                if (encodedAddrValue == 0 && refAddr != null) {
                    println("DEBUG: No scalar found, searching instruction bytes for encoded address");
                    // For x86-64, try to find 32-bit values in instruction bytes
                    // that could be the encoded address (this is a fallback)
                    for (int i = 0; i <= bytes.length - 4; i++) {
                        long value32 = ((long)(bytes[i] & 0xFF)) | 
                                      ((long)(bytes[i + 1] & 0xFF)) << 8 |
                                      ((long)(bytes[i + 2] & 0xFF)) << 16 |
                                      ((long)(bytes[i + 3] & 0xFF)) << 24;
                        
                        // Check if this value could be the encoded address
                        // For RIP-relative, it's a displacement, so we can't directly match
                        // But if it's an absolute address and points to data section, mask it
                        if (value32 > 0x10000 && value32 < 0x7FFFFFFF) {
                            try {
                                Address testAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value32);
                                MemoryBlock block = getMemoryBlock(testAddr);
                                if (block != null && !block.isExecute()) {
                                    // This could be the encoded address
                                    encodedAddrValue = value32;
                                    println("DEBUG: Found potential encoded address 0x" + Long.toHexString(encodedAddrValue) + " at byte offset " + i);
                                    break;
                                }
                            } catch (Exception e) {
                                // Skip
                            }
                        }
                    }
                }
            }
            
            // If we should mask, try to find and mask the encoded address/displacement
            if (shouldMask) {
                boolean found = false;
                
                // Check for segment override prefixes (64=FS, 65=GS, 2E=CS, 36=SS, 3E=DS)
                // For segment override instructions with data references, mask everything after the prefix
                int segmentPrefixPos = -1;
                int firstByte = bytes[0] & 0xFF;
                if (firstByte == 0x64 || firstByte == 0x65 || firstByte == 0x2E || 
                    firstByte == 0x36 || firstByte == 0x3E) {
                    segmentPrefixPos = 0;
                    println("DEBUG: Section 2b - Found segment override prefix 0x" + String.format("%02X", firstByte) + " at offset 0");
                }
                
                // If we have a segment override prefix and a data reference, mask everything after the prefix
                if (segmentPrefixPos >= 0 && refAddr != null) {
                    println("DEBUG: Section 2b - Masking all bytes after segment prefix (segment override with data reference)");
                    for (int i = segmentPrefixPos + 1; i < tok.length; i++) {
                        tok[i] = "?";
                    }
                    found = true; // We've masked everything, no need to search for specific addresses
                }
                
                // For memory addressing instructions, also mask the ModR/M byte (byte after opcode)
                // This handles cases like "8B 0D" -> "8B ?" where 0D is the ModR/M byte
                // But skip if we already masked everything due to segment override
                if (!found && bytes.length >= 2 && refs.length > 0) {
                    // Check if this is a memory reference instruction (has memory addressing)
                    boolean isMemoryRef = false;
                    for (Reference ref : refs) {
                        if (ref.getToAddress() != null) {
                            isMemoryRef = true;
                            break;
                        }
                    }
                    if (isMemoryRef) {
                        // Mask the ModR/M byte (typically byte 1 for most x86 instructions)
                        // But be careful - some instructions have prefixes, so ModR/M might be at different positions
                        // For simplicity, mask byte 1 if instruction starts with common opcodes (8B, 8A, 88, etc.)
                        int opcodeByte = bytes[0] & 0xFF;
                        if ((opcodeByte == 0x8B || opcodeByte == 0x8A || opcodeByte == 0x88 || 
                             opcodeByte == 0x89 || opcodeByte == 0x8D) && bytes.length >= 2) {
                            println("DEBUG: Section 2b - Masking ModR/M byte at offset 1 (opcode 0x" + String.format("%02X", opcodeByte) + ")");
                            tok[1] = "?";
                        }
                    }
                }
                
                // If we have an encoded address value, try to mask it
                if (encodedAddrValue != 0) {
                    println("DEBUG: Section 2b - attempting to mask encoded address 0x" + Long.toHexString(encodedAddrValue));
                } else {
                    println("DEBUG: Section 2b - should mask but no encoded address extracted, trying RIP-relative or direct search");
                }
                
                // For x86-64, addresses are typically encoded as 32-bit displacements (RIP-relative)
                // Always try RIP-relative displacement first when we have a reference address
                if (!found && refAddr != null) {
                    try {
                        long instructionEnd = insn.getAddress().getOffset() + bytes.length;
                        long displacement = refAddr.getOffset() - instructionEnd;
                        // Check if displacement fits in 32-bit signed range
                        if (displacement >= -0x80000000L && displacement <= 0x7FFFFFFFL) {
                            long displacement32 = displacement & 0xFFFFFFFFL;
                            println("DEBUG: Trying RIP-relative displacement 0x" + Long.toHexString(displacement32) + 
                                   " for address 0x" + Long.toHexString(encodedAddrValue) + 
                                   " (target: " + refAddr + ", instruction end: 0x" + Long.toHexString(instructionEnd) + ")");
                            
                            // Search for the 32-bit displacement in instruction bytes
                            for (int i = 0; i <= bytes.length - 4; i++) {
                                long value32 = ((long)(bytes[i] & 0xFF)) | 
                                              ((long)(bytes[i + 1] & 0xFF)) << 8 |
                                              ((long)(bytes[i + 2] & 0xFF)) << 16 |
                                              ((long)(bytes[i + 3] & 0xFF)) << 24;
                                
                                println("DEBUG: Comparing displacement value32=0x" + Long.toHexString(value32) + " at offset " + i + " with displacement32=0x" + Long.toHexString(displacement32));
                                
                                if (value32 == displacement32) {
                                    println("DEBUG: Section 2b - Found RIP-relative displacement at byte offset " + i + ", masking 4 bytes");
                                    for (int j = 0; j < 4 && i + j < tok.length; j++) {
                                        tok[i + j] = "?";
                                    }
                                    found = true;
                                    break;
                                }
                            }
                        } else {
                            println("DEBUG: Displacement " + displacement + " out of 32-bit signed range, skipping RIP-relative");
                        }
                    } catch (Exception e) {
                        println("DEBUG: Failed to calculate RIP-relative displacement: " + e.getMessage());
                    }
                }
                
                // Also try direct address matching (for absolute addresses or if RIP-relative failed)
                // Only do this if we have an encoded address value to search for
                if (!found && encodedAddrValue != 0) {
                    // Try 32-bit first, then 64-bit if needed
                    for (int addrSize = 4; addrSize <= 8 && !found; addrSize += 4) {
                        if (addrSize > bytes.length) break;
                        
                        // Search for the encoded address value in the instruction bytes (little-endian)
                        for (int i = 0; i <= bytes.length - addrSize; i++) {
                            long valueInBytes = 0;
                            for (int j = 0; j < addrSize; j++) {
                                if (i + j < bytes.length) {
                                    valueInBytes |= ((long)(bytes[i + j] & 0xFF)) << (j * 8);
                                }
                            }
                            
                            // Check if the value matches (for 32-bit, compare lower 32 bits)
                            long compareValue = encodedAddrValue;
                            if (addrSize == 4) {
                                compareValue = encodedAddrValue & 0xFFFFFFFFL;
                            }
                            
                            println("DEBUG: Comparing valueInBytes=0x" + Long.toHexString(valueInBytes) + " at offset " + i + " with compareValue=0x" + Long.toHexString(compareValue));
                            
                            if (valueInBytes == compareValue) {
                                println("DEBUG: Section 2b - Found encoded address at byte offset " + i + ", masking " + addrSize + " bytes");
                                // Found the address, mask it
                                for (int j = 0; j < addrSize && i + j < tok.length; j++) {
                                    tok[i + j] = "?";
                                }
                                found = true;
                                break; // Only mask first occurrence
                            }
                        }
                    }
                }
                
                // If still not found and we have a reference but no encoded address, try to find any 32-bit value
                // that could be a segment offset or displacement (for cases like GS:[0x58])
                if (!found && refAddr != null && encodedAddrValue == 0) {
                    println("DEBUG: Section 2b - Trying to find 32-bit offset/displacement in instruction bytes");
                    // Search for any 32-bit value in the instruction that could be the offset
                    // Look for values that are very small (likely offsets like 0x58) at the end of instruction
                    // Displacements/offsets are typically at the end of x86 instructions
                    for (int i = Math.max(0, bytes.length - 8); i <= bytes.length - 4 && !found; i++) {
                        long value32 = ((long)(bytes[i] & 0xFF)) | 
                                      ((long)(bytes[i + 1] & 0xFF)) << 8 |
                                      ((long)(bytes[i + 2] & 0xFF)) << 16 |
                                      ((long)(bytes[i + 3] & 0xFF)) << 24;
                        
                        // For segment offsets (like GS:[0x58]), the value is typically very small (< 0x1000)
                        // and the high bytes should be zero (little-endian: 58 00 00 00 = 0x00000058)
                        // Check if it's a small value with zero high bytes
                        if (value32 > 0 && value32 < 0x1000 && (value32 & 0xFFFF0000) == 0) {
                            println("DEBUG: Found potential 32-bit offset 0x" + Long.toHexString(value32) + " at byte offset " + i + " (bytes: " + 
                                   String.format("%02X %02X %02X %02X", bytes[i] & 0xFF, bytes[i+1] & 0xFF, bytes[i+2] & 0xFF, bytes[i+3] & 0xFF) + "), masking");
                            for (int j = 0; j < 4 && i + j < tok.length; j++) {
                                tok[i + j] = "?";
                            }
                            found = true;
                        }
                    }
                }
                
                if (!found) {
                    if (encodedAddrValue != 0) {
                        println("DEBUG: Section 2b - Encoded address 0x" + Long.toHexString(encodedAddrValue) + " not found in instruction bytes!");
                    } else {
                        println("DEBUG: Section 2b - Could not find encoded address/offset to mask");
                    }
                }
            }
        }

        // 2c) Direct byte scanning - scan instruction bytes for 32-bit values that look like addresses
        // This is a fallback when scalars aren't extracted from operands
        // Only use this if section 2b didn't find anything (to avoid double-masking)
        boolean section2bFound = false;
        for (int op = 0; op < insn.getNumOperands(); op++) {
            Reference[] refs = insn.getOperandReferences(op);
            if (refs.length > 0) {
                for (Reference ref : refs) {
                    Address refAddr = ref.getToAddress();
                    MemoryBlock block = getMemoryBlock(refAddr);
                    if (block != null && !block.isExecute()) {
                        section2bFound = true;
                        break;
                    }
                }
            }
        }
        
        if (!section2bFound) {
            println("DEBUG: Section 2c - Direct byte scanning for address-like values (2b found nothing)");
            for (int i = 0; i <= bytes.length - 4; i++) {
                // Extract 32-bit value (little-endian)
                long value32 = ((long)(bytes[i] & 0xFF)) | 
                              ((long)(bytes[i + 1] & 0xFF)) << 8 |
                              ((long)(bytes[i + 2] & 0xFF)) << 16 |
                              ((long)(bytes[i + 3] & 0xFF)) << 24;
                
                // Only check values that look like reasonable addresses (not too small, not immediates)
                // Filter out small values that are likely immediates (like 0x8, 0x58)
                if (value32 > 0x10000 && value32 < 0x7FFFFFFF) {
                    try {
                        Address testAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value32);
                        MemoryBlock block = getMemoryBlock(testAddr);
                        if (block != null && !block.isExecute()) {
                            println("DEBUG: Found address-like value 0x" + Long.toHexString(value32) + " at byte offset " + i + 
                                   " -> " + testAddr + " (data section), masking");
                            for (int j = 0; j < 4 && i + j < tok.length; j++) {
                                tok[i + j] = "?";
                            }
                        }
                    } catch (Exception e) {
                        // Invalid address, skip
                    }
                }
            }
        } else {
            println("DEBUG: Section 2c - Skipping (2b already found references)");
        }

        // 2d) aggressive scalar checking - check ALL scalars in ALL operands for data section addresses
        // This is more aggressive and doesn't depend on operand types, references, or relocations
        println("DEBUG: Checking instruction at " + insnStart + " with " + insn.getNumOperands() + " operands");
        for (int op = 0; op < insn.getNumOperands(); op++) {
            Object[] opObjects = insn.getOpObjects(op);
            println("DEBUG: Operand " + op + " has " + opObjects.length + " objects");
            
            for (Object obj : opObjects) {
                if (obj instanceof Scalar) {
                    Scalar scalar = (Scalar) obj;
                    long scalarValue = scalar.getUnsignedValue();
                    int scalarSize = Math.max(1, (scalar.bitLength() + 7) / 8);
                    println("DEBUG: Found scalar in opObjects: value=0x" + Long.toHexString(scalarValue) + ", size=" + scalarSize);
                    
                    // Only check scalars that are 32-bit or 64-bit (likely addresses, not small immediates)
                    // Also skip small values (< 0x10000) that are likely immediates, not addresses
                    if (scalarSize >= 4 && scalarSize <= 8 && scalarValue >= 0x10000) {
                        boolean shouldMask = false;
                        String reason = "";
                        
                        // Try to create address from scalar value and check if it points to data section
                        try {
                            Address testAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(scalarValue);
                            MemoryBlock block = getMemoryBlock(testAddr);
                            if (block != null) {
                                println("DEBUG: Scalar 0x" + Long.toHexString(scalarValue) + " -> address " + testAddr + ", block=" + block.getName() + ", executable=" + block.isExecute());
                                if (!block.isExecute()) {
                                    shouldMask = true;
                                    reason = "points to data section";
                                }
                            } else {
                                println("DEBUG: Scalar 0x" + Long.toHexString(scalarValue) + " -> address " + testAddr + " has no memory block");
                            }
                        } catch (Exception e) {
                            println("DEBUG: Failed to create address from scalar 0x" + Long.toHexString(scalarValue) + " in default space: " + e.getMessage());
                            // Try with instruction's address space
                            try {
                                Address testAddr = insn.getAddress().getAddressSpace().getAddress(scalarValue);
                                MemoryBlock block = getMemoryBlock(testAddr);
                                if (block != null) {
                                    println("DEBUG: Scalar 0x" + Long.toHexString(scalarValue) + " -> address " + testAddr + " (instr space), block=" + block.getName() + ", executable=" + block.isExecute());
                                    if (!block.isExecute()) {
                                        shouldMask = true;
                                        reason = "points to data section (instr space)";
                                    }
                                }
                            } catch (Exception e2) {
                                println("DEBUG: Failed to create address from scalar 0x" + Long.toHexString(scalarValue) + " in instr space: " + e2.getMessage());
                            }
                        }
                        
                        // Also check if scalar points to external symbol
                        if (!shouldMask) {
                            try {
                                Address testAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(scalarValue);
                                ghidra.program.model.symbol.Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(testAddr);
                                if (symbol != null) {
                                    println("DEBUG: Scalar 0x" + Long.toHexString(scalarValue) + " -> symbol " + symbol.getName() + ", external=" + symbol.isExternal());
                                    if (symbol.isExternal()) {
                                        shouldMask = true;
                                        reason = "external symbol";
                                    }
                                }
                            } catch (Exception e) {
                                // Skip
                            }
                        }
                        
                        // If we should mask, find and mask the scalar bytes in instruction encoding
                        if (shouldMask) {
                            println("DEBUG: Should mask scalar 0x" + Long.toHexString(scalarValue) + " (" + reason + ")");
                            // Search for the scalar value in the instruction bytes (little-endian)
                            boolean found = false;
                            for (int i = 0; i <= bytes.length - scalarSize; i++) {
                                long valueInBytes = 0;
                                for (int j = 0; j < scalarSize; j++) {
                                    if (i + j < bytes.length) {
                                        valueInBytes |= ((long)(bytes[i + j] & 0xFF)) << (j * 8);
                                    }
                                }
                                
                                // Check if the value matches (for 32-bit, compare lower 32 bits)
                                long compareValue = scalarValue;
                                if (scalarSize == 4) {
                                    compareValue = scalarValue & 0xFFFFFFFFL;
                                }
                                
                                if (valueInBytes == compareValue) {
                                    println("DEBUG: Found scalar at byte offset " + i + ", masking");
                                    // Found the scalar, mask it
                                    for (int j = 0; j < scalarSize && i + j < tok.length; j++) {
                                        tok[i + j] = "?";
                                    }
                                    found = true;
                                    break; // Only mask first occurrence
                                }
                            }
                            if (!found) {
                                println("DEBUG: Scalar value 0x" + Long.toHexString(scalarValue) + " not found in instruction bytes!");
                            }
                        }
                    } else if (scalarSize >= 4 && scalarSize <= 8 && scalarValue < 0x10000) {
                        println("DEBUG: Skipping scalar 0x" + Long.toHexString(scalarValue) + " (too small, likely immediate)");
                    }
                }
            }
            
            // Also try operand representation list (more reliable for some instruction types)
            try {
                Scalar scalar = getScalarOperand(insn.getDefaultOperandRepresentationList(op));
                if (scalar != null) {
                    long scalarValue = scalar.getUnsignedValue();
                    int scalarSize = Math.max(1, (scalar.bitLength() + 7) / 8);
                    println("DEBUG: Found scalar in representation list (op " + op + "): value=0x" + Long.toHexString(scalarValue) + ", size=" + scalarSize);
                    
                    // Skip small values (< 0x10000) that are likely immediates, not addresses
                    if (scalarSize >= 4 && scalarSize <= 8 && scalarValue >= 0x10000) {
                        boolean shouldMask = false;
                        
                        // Check if scalar points to data section or external symbol
                        try {
                            Address testAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(scalarValue);
                            MemoryBlock block = getMemoryBlock(testAddr);
                            if (block != null && !block.isExecute()) {
                                shouldMask = true;
                                println("DEBUG: Representation scalar 0x" + Long.toHexString(scalarValue) + " points to data section, masking");
                            } else {
                                ghidra.program.model.symbol.Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(testAddr);
                                if (symbol != null && symbol.isExternal()) {
                                    shouldMask = true;
                                    println("DEBUG: Representation scalar 0x" + Long.toHexString(scalarValue) + " points to external symbol, masking");
                                }
                            }
                        } catch (Exception e) {
                            // Try instruction's address space
                            try {
                                Address testAddr = insn.getAddress().getAddressSpace().getAddress(scalarValue);
                                MemoryBlock block = getMemoryBlock(testAddr);
                                if (block != null && !block.isExecute()) {
                                    shouldMask = true;
                                    println("DEBUG: Representation scalar 0x" + Long.toHexString(scalarValue) + " points to data section (instr space), masking");
                                }
                            } catch (Exception e2) {
                                // Skip
                            }
                        }
                        
                        if (shouldMask) {
                            maskScalarInInstruction(insn, op, scalar, tok, bytes);
                        }
                    } else if (scalarSize >= 4 && scalarSize <= 8 && scalarValue < 0x10000) {
                        println("DEBUG: Skipping representation scalar 0x" + Long.toHexString(scalarValue) + " (too small, likely immediate)");
                    }
                }
            } catch (Exception e) {
                // Skip if representation list access fails
            }
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

        // 7) Mask ModR/M and SIB bytes for REX-prefixed memory-addressing instructions
        // This handles cases like "48 8B 04 C8" -> "48 ? ? ?" for robustness
        // REX prefix is 0x40-0x4F, where 0x48 = REX.W (64-bit operand size)
        if (bytes.length >= 4) {
            int firstByte = bytes[0] & 0xFF;
            // Check for REX prefix (0x40-0x4F)
            if (firstByte >= 0x40 && firstByte <= 0x4F) {
                // Check if instruction has memory addressing
                // Look for memory operands (operands with references, ADDRESS type, or brackets in representation)
                boolean hasMemoryAddressing = false;
                for (int op = 0; op < insn.getNumOperands(); op++) {
                    int optype = insn.getOperandType(op);
                    // Check for memory addressing indicators
                    if (insn.getOperandReferences(op).length > 0 || 
                        (optype & OperandType.ADDRESS) != 0 ||
                        (optype & OperandType.DATA) != 0) {
                        hasMemoryAddressing = true;
                        println("DEBUG: Section 7 - REX instruction has memory addressing (op " + op + " has refs or ADDRESS/DATA type)");
                        break;
                    }
                    // Check operand representation for bracket notation (memory addressing)
                    try {
                        List<?> opRep = insn.getDefaultOperandRepresentationList(op);
                        String opRepStr = opRep.toString();
                        if (opRepStr.contains("[") || opRepStr.contains("PTR")) {
                            hasMemoryAddressing = true;
                            println("DEBUG: Section 7 - REX instruction has memory addressing (op " + op + " has bracket/PTR in representation)");
                            break;
                        }
                    } catch (Exception e) {
                        // Skip if representation access fails
                    }
                }
                
                if (hasMemoryAddressing) {
                    // Mask opcode + ModR/M + SIB bytes (typically 3 bytes after REX prefix)
                    // For "48 8B 04 C8": mask bytes 1, 2, 3 (8B, 04, C8) -> "48 ? ? ?"
                    // IMPORTANT: Always preserve the REX prefix (byte 0) even if it was masked earlier
                    println("DEBUG: Section 7 - Masking opcode+ModR/M+SIB (bytes 1-3) for REX-prefixed memory instruction at " + insn.getAddress());
                    // Restore the REX prefix byte (byte 0) if it was masked
                    tok[0] = String.format("%02X", bytes[0] & 0xFF);
                    // Mask bytes 1-3 (opcode, ModR/M, SIB)
                    for (int i = 1; i < Math.min(4, bytes.length); i++) {
                        tok[i] = "?";
                    }
                } else {
                    println("DEBUG: Section 7 - REX instruction at " + insn.getAddress() + " does not have memory addressing, skipping");
                }
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

    /**
     * Extracts a scalar from an operand's default representation list.
     * Similar to CreateRelocationBasedOperandReferences.getScalarOperand()
     *
     * @param defaultOperandRepresentationList The operand representation list
     * @return The scalar if found and unique, null otherwise
     */
    private Scalar getScalarOperand(List<Object> defaultOperandRepresentationList) {
        Scalar s = null;
        for (Object obj : defaultOperandRepresentationList) {
            if (obj instanceof String) {
                continue;
            }
            if (obj instanceof Character) {
                continue;
            }
            if (obj instanceof Scalar) {
                if (s != null) {
                    // more than one scalar found
                    return null;
                }
                s = (Scalar) obj;
            } else {
                // non-scalar found
                return null;
            }
        }
        return s;
    }

    /**
     * Masks the bytes of a scalar operand in the instruction encoding.
     * Finds the scalar value in the instruction bytes and masks it.
     *
     * @param insn The instruction
     * @param opIndex The operand index
     * @param scalar The scalar to mask
     * @param tok The token array to modify
     * @param bytes The instruction bytes
     */
    private void maskScalarInInstruction(Instruction insn, int opIndex, Scalar scalar, String[] tok, byte[] bytes) {
        long scalarValue = scalar.getUnsignedValue();
        int scalarSize = Math.max(1, (scalar.bitLength() + 7) / 8);
        
        // Search for the scalar value in the instruction bytes (little-endian)
        for (int i = 0; i <= bytes.length - scalarSize; i++) {
            long valueInBytes = 0;
            for (int j = 0; j < scalarSize; j++) {
                if (i + j < bytes.length) {
                    valueInBytes |= ((long)(bytes[i + j] & 0xFF)) << (j * 8);
                }
            }
            
            if (valueInBytes == scalarValue) {
                // Found the scalar, mask it
                for (int j = 0; j < scalarSize && i + j < tok.length; j++) {
                    tok[i + j] = "?";
                }
                break; // Only mask first occurrence
            }
        }
    }
}