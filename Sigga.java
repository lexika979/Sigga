//A robust, patch-resistant signature generator for Ghidra.
//Combines sliding-window algorithms, XRef detection, and aggressive smart-masking.
//Automatically retries with lower strictness if a unique signature cannot be found.
//@author lexika, Krixx1337, outercloudstudio
//@category Functions
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
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
import java.util.*;

public class Sigga extends GhidraScript {

    // --- CONFIGURATION ---
    private static final int MAX_INSTRUCTIONS_TO_SCAN = 200;
    private static final int MIN_WINDOW_BYTES = 5;    // Minimum length of a sig
    private static final int MAX_WINDOW_BYTES = 128;  // Maximum length of a sig; capped to avoid endless scans
    private static final int HEAD_CHECK_SPAN = 3;     // First N bytes to check for stability
    private static final int XREF_CONTEXT_INSTRUCTIONS = 8; // How many instructions to grab for XRef sigs
    private static final int MAX_START_OFFSET = 64;   // Only start sigs within first 64 bytes of function

    /**
     * Enum to control how aggressive the masking logic is.
     */
    private enum MaskProfile {
        STRICT,    // Mask anything that looks like an address, offset, or variable (Best for patches)
        MINIMAL    // Only mask relocations and direct branches (Desperation mode)
    }

    /**
     * Container for a generated signature.
     */
    private static class SigResult {
        String signature;
        Address address;
        long offset; // Offset from start of function/block
        int quality; // 100 = Best, 0 = Worst
        String tier;

        public SigResult(String signature, Address address, long offset, int quality, String tier) {
            this.signature = signature;
            this.address = address;
            this.offset = offset;
            this.quality = quality;
            this.tier = tier;
        }
    }

    /**
     * Data structure to map tokens back to instruction boundaries for optimization.
     */
    private static class TokenData {
        List<String> tokens;
        Set<Integer> instructionStartIndices; // Allows O(1) lookup

        public TokenData(List<String> tokens, Set<Integer> starts) {
            this.tokens = tokens;
            this.instructionStartIndices = starts;
        }
    }

    @Override
    public void run() throws Exception {
        if (currentLocation == null) {
            printerr("Sigga: No cursor location found. Please run this script from the Listing window.");
            return;
        }

        Function func = getFunctionContaining(currentLocation.getAddress());
        if (func == null) {
            printerr("Sigga: Cursor is not inside a function.");
            return;
        }

        println("Sigga: Analyzing " + func.getName() + " @ " + func.getEntryPoint());
        
        try {
            generateSignatureRoutine(func);
        } catch (CancelledException e) {
            println("Sigga: Generation cancelled by user.");
        }
    }

    private void generateSignatureRoutine(Function func) throws Exception {
        List<Instruction> instructions = getInstructions(func.getBody(), MAX_INSTRUCTIONS_TO_SCAN);
        
        // --- TIER 1 & 2: DIRECT SCAN (Optimized One-Pass) ---
        // We scan once with strict tokens. If we find a unique sig, we check its head.
        // If head is solid -> Tier 1. If head is weak -> Tier 2.
        monitor.setMessage("Scanning for Direct Signature...");
        TokenData data = tokenizeInstructions(instructions, MaskProfile.STRICT);
        // Tier 1: Strict masking with a solid head (first byte must be concrete, offsets masked).
        // Tier 2: Same tokens but allows a weak head if uniqueness requires it.
        SigResult directResult = findCheapestSignature(data, func.getEntryPoint());
        
        if (directResult != null) {
            finish(directResult);
            return;
        }
        
        println("... Direct scan failed. Function is likely generic/duplicate.");

        // --- TIER 3: XREF SCAN ---
        monitor.setMessage("Checking Tier 3 (XRefs)...");
        SigResult xrefResult = tryXRefSignature(func);
        if (xrefResult != null) {
            finish(xrefResult);
            return;
        }

        println("... Tier 3 failed (No unique XRefs found).");

        // --- TIER 4: DESPERATION ---
        monitor.setMessage("Checking Tier 4 (Minimal)...");
        TokenData looseData = tokenizeInstructions(instructions, MaskProfile.MINIMAL);
        SigResult looseResult = findCheapestSignature(looseData, func.getEntryPoint());
        
        if (looseResult != null) {
            looseResult.tier = "Tier 4 (Low Stability / Desperation)";
            finish(looseResult);
            return;
        }

        popup("Failed to generate a unique signature. \n\n" +
              "This function appears to be identical to many others in the binary \n" +
              "and has no unique cross-references.");
    }

    private void finish(SigResult result) {
        println("==================================================");
        println(" SIGGA SUCCESS - " + result.tier);
        println("==================================================");
        println("Signature:  " + result.signature);
        println("Address:    " + result.address);
        println("Offset:     +" + Long.toHexString(result.offset).toUpperCase());
        println("Quality:    " + result.quality + "/100");
        println("==================================================");

        copyToClipboard(result.signature);
        println(">> Copied to clipboard.");
    }

    /**
     * Sliding Window Algorithm (optimized):
     * Finds the shortest unique substring of tokens by:
     * 1. Only starting at instruction boundaries (and near the head of the function).
     * 2. Only checking uniqueness at instruction boundaries to cut redundant checks.
     * 3. Classifying Tier 1 vs Tier 2 automatically by inspecting the head bytes.
     */
    private SigResult findCheapestSignature(TokenData data, Address startAddr) throws CancelledException {
        List<String> tokens = data.tokens;
        int n = tokens.size();

        // Iterate through possible start positions (i)
        for (int i = 0; i < n; i++) {
            monitor.checkCancelled();

            // 1. Only start at instruction boundaries
            if (!data.instructionStartIndices.contains(i)) continue;
            // 2. Limit start depth (don't scan deep into massive functions)
            // Use >= to match the logic of "first X bytes" (0-indexed)
            if (i >= MAX_START_OFFSET) break;

            StringBuilder sigBuilder = new StringBuilder();
            int byteCount = 0;

            // Grow the window (j)
            for (int j = i; j < n; j++) {
                String tok = tokens.get(j);
                if (sigBuilder.length() > 0) sigBuilder.append(" ");
                sigBuilder.append(tok);
                byteCount++;

                if (byteCount < MIN_WINDOW_BYTES) continue;
                if (byteCount > MAX_WINDOW_BYTES) break;

                // 3. OPTIMIZATION: Only check uniqueness if we represent a full instruction.
                // We assume we are at the end of an instruction if (j+1) is the start of a new one,
                // or if we have reached the total token count.
                boolean isInstructionEnd = (j + 1 == n) || data.instructionStartIndices.contains(j + 1);
                
                if (!isInstructionEnd) {
                    continue; 
                }

                // Check uniqueness
                String currentSig = sigBuilder.toString();
                if (isSignatureUnique(currentSig)) {
                    // CLEANUP: Trim trailing wildcards if possible (e.g. "A B ? ?" -> "A B")
                    String finalSig = trimTrailingWildcards(currentSig);
                    
                    // Found a unique sig. Classify it.
                    boolean solidHead = !isHeadWeak(tokens, i);
                    String tier = solidHead ? "Tier 1 (High Stability, Direct)" : "Tier 2 (High Stability, Loose Head)";
                    int quality = solidHead ? 100 : 90;
                    
                    return new SigResult(finalSig, startAddr, i, quality, tier);
                }
            }
        }
        return null;
    }

    private String trimTrailingWildcards(String sig) {
        String[] parts = sig.split(" ");
        int trimCount = 0;
        // Count trailing wildcards
        for (int i = parts.length - 1; i >= 0; i--) {
            if (parts[i].equals("?")) trimCount++;
            else break;
        }
        
        if (trimCount == 0) return sig;

        // Ensure we don't trim below minimum length
        if (parts.length - trimCount < MIN_WINDOW_BYTES) {
            trimCount = parts.length - MIN_WINDOW_BYTES;
            if (trimCount <= 0) return sig;
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < parts.length - trimCount; i++) {
            if (i > 0) sb.append(" ");
            sb.append(parts[i]);
        }
        return sb.toString();
    }

    private boolean isHeadWeak(List<String> tokens, int startIndex) {
        if (startIndex >= tokens.size()) return true;
        
        // RULE 1: The very first byte MUST be solid (Industry Standard)
        // This prevents signatures like "? 8B EC" which break some C++ scanners.
        if (tokens.get(startIndex).contains("?")) return true;
        
        // RULE 2: Check density of the first few bytes
        int checkLen = Math.min(HEAD_CHECK_SPAN, tokens.size() - startIndex);
        int wildcards = 0;
        for (int k = 0; k < checkLen; k++) {
            if (tokens.get(startIndex + k).contains("?")) wildcards++;
        }
        // If more than 50% of the head is wildcards, consider it weak
        return wildcards > (checkLen / 2);
    }

    // ============================================================================================
    //  MASKING & TOKENIZATION
    // ============================================================================================

    private TokenData tokenizeInstructions(List<Instruction> instructions, MaskProfile profile) throws MemoryAccessException {
        List<String> allTokens = new ArrayList<>();
        Set<Integer> starts = new HashSet<>();
        
        int currentOffset = 0;

        for (Instruction insn : instructions) {
            starts.add(currentOffset);

            String[] tokens = new String[insn.getLength()];
            byte[] bytes = insn.getBytes();
            
            // 1. Base tokens (hex)
            for (int i = 0; i < bytes.length; i++) {
                tokens[i] = String.format("%02X", bytes[i]);
            }

            // 2. Mask relocations (absolute addresses are volatile)
            maskRelocations(insn, tokens);
            // 3. Mask branches (JMP/CALL/JCC) which always carry variable displacements
            maskBranches(insn, tokens);

            if (profile == MaskProfile.STRICT) {
                // 4. Aggressively mask operands that reference data/external symbols
                maskOperandsSmart(insn, tokens);
            }

            for (String t : tokens) {
                allTokens.add(t);
            }
            currentOffset += tokens.length;
        }
        return new TokenData(allTokens, starts);
    }

    private void maskRelocations(Instruction insn, String[] tokens) {
        Address start = insn.getMinAddress();
        Address end = insn.getMaxAddress();
        RelocationTable rt = currentProgram.getRelocationTable();
        Iterator<Relocation> rels = rt.getRelocations(new AddressSet(start, end));

        while (rels.hasNext()) {
            Relocation r = rels.next();
            int offset = (int) r.getAddress().subtract(start);
            // Default mask length 4
            int len = 4;
            for (int i = 0; i < len && (offset + i) < tokens.length; i++) {
                tokens[offset + i] = "?";
            }
        }
    }

    private void maskBranches(Instruction insn, String[] tokens) {
        if (insn.getFlowType().isCall() || insn.getFlowType().isJump()) {
            // Safety check: if byte 0 was already masked by relocation, don't parse it
            if (tokens[0].contains("?")) return;

            int b0 = Integer.parseInt(tokens[0], 16);
            // Heuristic: mask rel32 for CALL/JMP (E8/E9) to avoid volatile branch targets
            if (b0 == 0xE8 || b0 == 0xE9) {
                for (int i = 1; i < tokens.length; i++) tokens[i] = "?";
            }
            // Short jumps (EB / 7x) – mask the displacement byte
            else if (tokens.length == 2 && (b0 == 0xEB || (b0 & 0xF0) == 0x70)) {
                 tokens[1] = "?";
            }
            // Long conditional (0F 8x) – mask displacement dword
            else if (tokens.length >= 6 && b0 == 0x0F) {
                // Safety check for 0F 8x check
                if (!tokens[1].contains("?") && (Integer.parseInt(tokens[1], 16) & 0xF0) == 0x80) {
                    for (int i = 2; i < tokens.length; i++) tokens[i] = "?";
                }
            }
        }
    }

    /**
     * The "Paranoid" masking logic.
     * Identifies operands that point to data/external symbols and masks their byte representation.
     */
    private void maskOperandsSmart(Instruction insn, String[] tokens) {
        byte[] bytes;
        try { bytes = insn.getBytes(); } catch (Exception e) { return; }

        int numOps = insn.getNumOperands();
        for (int op = 0; op < numOps; op++) {
            boolean shouldMask = false;
            Reference[] refs = insn.getOperandReferences(op);

            for (Reference ref : refs) {
                Address toAddr = ref.getToAddress();
                if (toAddr == null) continue;
                if (toAddr.isExternalAddress()) { shouldMask = true; break; }
                MemoryBlock block = getMemoryBlock(toAddr);
                if (block != null && !block.isExecute()) { shouldMask = true; break; }
            }

            if (!shouldMask) {
                Object[] opObjects = insn.getOpObjects(op);
                for (Object obj : opObjects) {
                    if (obj instanceof Scalar) {
                        Scalar s = (Scalar) obj;
                        long val = s.getUnsignedValue();
                        // Ignore small immediates (likely loop counters or offsets < 64KB)
                        if (val > 0x10000) {
                            Address possibleAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(val);
                            MemoryBlock block = getMemoryBlock(possibleAddr);
                            if (block != null && !block.isExecute()) shouldMask = true;
                        }
                    }
                }
            }

            if (shouldMask) {
                // If we found a data ref, we need to mask the bytes in the instruction that define it.
                // 1. RIP-relative search – locate displacement bytes that encode the data target
                for (Reference ref : refs) {
                    Address toAddr = ref.getToAddress();
                    if (toAddr != null) {
                        long target = toAddr.getOffset();
                        long instrEnd = insn.getAddress().add(bytes.length).getOffset();
                        long disp = target - instrEnd; 
                        // Search for the displacement (4 bytes)
                        maskValueInBytes(tokens, bytes, disp, 4);
                    }
                }
                // 2. Absolute scalar search – mask immediates that look like pointers
                Object[] opObjects = insn.getOpObjects(op);
                for (Object obj : opObjects) {
                    if (obj instanceof Scalar) {
                        long val = ((Scalar)obj).getUnsignedValue();
                        maskValueInBytes(tokens, bytes, val, 4); 
                        maskValueInBytes(tokens, bytes, val, 8); 
                    }
                }
            }
        }
    }

    private boolean hasStackReg(Instruction insn) {
        for (int i=0; i<insn.getNumOperands(); i++) {
             for (Object o : insn.getOpObjects(i)) {
                 if (o instanceof Register) {
                     String n = ((Register)o).getName().toUpperCase();
                     if (n.contains("SP") || n.contains("BP")) return true;
                 }
             }
        }
        return false;
    }

    /**
     * Helper to find a value (little endian) in the byte array and mask it.
     */
    private void maskValueInBytes(String[] tokens, byte[] bytes, long value, int size) {
        if (size > 8 || bytes.length < size) return;
        for (int i = 0; i <= bytes.length - size; i++) {
            long currentVal = 0;
            // Read bytes as little endian
            for (int k = 0; k < size; k++) currentVal |= ((long)(bytes[i+k] & 0xFF)) << (k*8);
            
            // Mask if matches (handle 32-bit sign extension comparison)
            boolean match = false;
            if (size == 4) { if ((int)currentVal == (int)value) match = true; } 
            else { if (currentVal == value) match = true; }

            if (match) {
                for (int k=0; k<size; k++) tokens[i+k] = "?";
            }
        }
    }

    // ============================================================================================
    //  XREF FALLBACK LOGIC
    // ============================================================================================

    private SigResult tryXRefSignature(Function targetFunc) throws Exception {
        Address funcStart = targetFunc.getEntryPoint();
        Reference[] refs = getReferencesTo(funcStart);
        
        for (Reference ref : refs) {
            if (!ref.getReferenceType().isCall()) continue;
            
            Address callSite = ref.getFromAddress();
            Function callerFunc = getFunctionContaining(callSite);
            if (callerFunc == null) continue;

            List<Instruction> context = new ArrayList<>();
            Instruction insn = getInstructionAt(callSite); 
            if (insn == null) continue;
            context.add(insn);
            // Strategy: Signature the call instruction plus the next few instructions for unique context.
            Instruction next = insn.getNext();
            for(int k=0; k<XREF_CONTEXT_INSTRUCTIONS && next != null; k++) {
                 context.add(next);
                 next = next.getNext();
            }

            TokenData data = tokenizeInstructions(context, MaskProfile.STRICT);
            StringBuilder sb = new StringBuilder();
            for(String t : data.tokens) sb.append(t).append(" ");
            String fullSig = sb.toString().trim();
            
            if (isSignatureUnique(fullSig)) {
                String finalSig = trimTrailingWildcards(fullSig);
                return new SigResult(finalSig, callSite, 0, 80, "Tier 3 (XRef / Caller)");
            }
        }
        return null;
    }

    // ============================================================================================
    //  UTILITIES
    // ============================================================================================

    private boolean isSignatureUnique(String sigStr) throws CancelledException {
        try {
            monitor.checkCancelled();
            ByteSignature sig = new ByteSignature(sigStr);
            Memory mem = currentProgram.getMemory();
            
            // Find first match
            Address firstMatch = mem.findBytes(currentProgram.getMinAddress(), sig.bytes, sig.mask, true, monitor);
            if (firstMatch == null) return false; 
            
            // Find second match (starting 1 byte after first)
            Address secondMatch = mem.findBytes(firstMatch.add(1), currentProgram.getMaxAddress(), sig.bytes, sig.mask, true, monitor);
            return secondMatch == null;
        } catch (CancelledException e) {
            throw e;
        } catch (Exception e) {
            return false;
        }
    }
    
    private List<Instruction> getInstructions(AddressSetView body, int max) {
        List<Instruction> list = new ArrayList<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(body, true);
        int count = 0;
        while (it.hasNext() && count < max) {
            list.add(it.next());
            count++;
        }
        return list;
    }

    private void copyToClipboard(String text) {
        try {
            Clipboard c = Toolkit.getDefaultToolkit().getSystemClipboard();
            c.setContents(new StringSelection(text), null);
        } catch (Exception e) {
            println("Clipboard copy failed: " + e.getMessage());
        }
    }

    /**
     * Helper to parse IDA style "A1 ?? BB" strings
     */
    private static class ByteSignature {
        public byte[] bytes;
        public byte[] mask;

        public ByteSignature(String s) {
            s = s.trim().replaceAll("\\s+", " ");
            String[] parts = s.split(" ");
            bytes = new byte[parts.length];
            mask = new byte[parts.length];
            for (int i = 0; i < parts.length; i++) {
                if (parts[i].contains("?")) {
                    bytes[i] = 0;
                    mask[i] = 0;
                } else {
                    bytes[i] = (byte) Integer.parseInt(parts[i], 16);
                    mask[i] = (byte) 0xFF;
                }
            }
        }
    }
}