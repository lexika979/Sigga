//A robust x86/x64 signature generator for Ghidra.
//Combines sliding-window algorithms, XRef detection, and aggressive smart-masking.
//Automatically retries with lower strictness if a unique signature cannot be found.
//@author lexika, Krixx1337, outercloudstudio, Bello
//@category Functions
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Mask;
import ghidra.program.model.lang.Processor;
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

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.awt.GridLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.*;
import javax.swing.*;

public class Sigga extends GhidraScript {

    // --- CONFIGURATION (defaults, overridable via dialog) ---
    private static final int DEFAULT_MAX_INSTRUCTIONS_TO_SCAN = 200;
    private static final int DEFAULT_MIN_WINDOW_BYTES = 8;
    private static final int DEFAULT_MAX_WINDOW_BYTES = 128;
    private static final int DEFAULT_HEAD_CHECK_SPAN = 3;
    private static final int DEFAULT_XREF_CONTEXT_INSTRUCTIONS = 8;
    private static final int DEFAULT_MAX_START_OFFSET = 64;
    private static final int MIN_CONCRETE_ANCHOR_BYTES = 4;
    private static final int MAX_ANCHOR_MATCHES_TO_VERIFY = 4096;
    private static final int MAX_X86_INSTRUCTION_BYTES = 15;

    private int MAX_INSTRUCTIONS_TO_SCAN = DEFAULT_MAX_INSTRUCTIONS_TO_SCAN;
    private int MIN_WINDOW_BYTES = DEFAULT_MIN_WINDOW_BYTES;
    private int MAX_WINDOW_BYTES = DEFAULT_MAX_WINDOW_BYTES;
    private int HEAD_CHECK_SPAN = DEFAULT_HEAD_CHECK_SPAN;
    private int XREF_CONTEXT_INSTRUCTIONS = DEFAULT_XREF_CONTEXT_INSTRUCTIONS;
    private int MAX_START_OFFSET = DEFAULT_MAX_START_OFFSET;
    private boolean ALLOW_XREF_FALLBACK = true;
    private final Map<String, Boolean> uniquenessCache = new HashMap<>();
    private final Map<String, ByteSignature> parsedSignatureCache = new HashMap<>();

    /**
     * Enum to control how aggressive the masking logic is.
     */
    private enum MaskProfile {
        STRICT,    // Mask anything that looks like an address, offset, or variable (Best for patches)
        MINIMAL    // Only mask relocations and direct branches (Desperation mode)
    }

    /**
     * Enum to select where signature generation starts.
     */
    private enum StartMode {
        FUNCTION_START, // Begin at the function's entry point (most stable)
        CURRENT_ADDRESS // Begin at the cursor's current location
    }

    /**
     * Container for a generated signature.
     */
    private static class SigResult {
        String signature;
        Address address;
        long offset; // Offset from start of function/block
        int quality; // Heuristic confidence only; not a patch-survival guarantee.
        String tier;
        String resolver;

        public SigResult(String signature, Address address, long offset, int quality, String tier) {
            this(signature, address, offset, quality, tier, null);
        }

        public SigResult(String signature, Address address, long offset, int quality, String tier,
                         String resolver) {
            this.signature = signature;
            this.address = address;
            this.offset = offset;
            this.quality = quality;
            this.tier = tier;
            this.resolver = resolver;
        }
    }

    private static class XRefResolver {
        String kind;
        int instructionOffset;
        int displacementOffset;
        int displacementSize;
        int instructionLength;

        XRefResolver(String kind, int displacementOffset, int displacementSize, int instructionLength) {
            this.kind = kind;
            this.displacementOffset = displacementOffset;
            this.displacementSize = displacementSize;
            this.instructionLength = instructionLength;
        }
    }

    private static class XRefCandidate {
        SigResult result;
        boolean weakHead;
        Address referenceAddress;

        XRefCandidate(SigResult result, boolean weakHead, Address referenceAddress) {
            this.result = result;
            this.weakHead = weakHead;
            this.referenceAddress = referenceAddress;
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
        if (!isSupportedX86Program()) {
            printerr("Sigga: Only 32-bit x86 and 64-bit x86 programs are supported.");
            return;
        }

        if (currentLocation == null) {
            printerr("Sigga: No cursor location found. Please run this script from the Listing window.");
            return;
        }

        Address cursorAddr = currentLocation.getAddress();
        Function func = getFunctionContaining(cursorAddr);
        if (func == null) {
            printerr("Sigga: Cursor is not inside a function.");
            return;
        }

        StartMode mode = showSettingsDialog(func, cursorAddr);
        if (mode == null) {
            println("Sigga: Cancelled by user.");
            return;
        }

        Address startAddr = (mode == StartMode.CURRENT_ADDRESS) ? cursorAddr : func.getEntryPoint();
        println("Sigga: Analyzing " + func.getName() + " @ " + startAddr + " (" + mode + ")");

        try {
            generateSignatureRoutine(func, startAddr);
        } catch (CancelledException e) {
            println("Sigga: Generation cancelled by user.");
        }
    }

    // Returns the selected StartMode, or null if cancelled.
    private StartMode showSettingsDialog(Function func, Address cursorAddr) throws Exception {
        StartMode[] selectedMode = new StartMode[] { StartMode.FUNCTION_START };
        boolean[] confirmed = new boolean[] { false };

        Runnable dialogTask = () -> {
            JDialog dialog = new JDialog((Frame) null, "Sigga - Settings", true);
            dialog.setLayout(new BorderLayout(10, 10));
            dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);

            // --- Info panel ---
            JPanel infoPanel = new JPanel(new GridLayout(2, 1, 4, 4));
            infoPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 0, 10));
            infoPanel.add(new JLabel("Function: " + func.getName()));
            infoPanel.add(new JLabel("Entry: " + func.getEntryPoint() + "  |  Cursor: " + cursorAddr));
            dialog.add(infoPanel, BorderLayout.NORTH);

            // --- Generation options panel ---
            JPanel modePanel = new JPanel(new GridLayout(4, 1, 4, 4));
            modePanel.setBorder(BorderFactory.createTitledBorder("Generation Options"));
            modePanel.add(new JLabel("Choose where the signature pattern begins scanning from:"));

            JRadioButton fromFuncStart = new JRadioButton("From function start (" + func.getEntryPoint() + ")", true);
            JRadioButton fromCursor = new JRadioButton("From current address (" + cursorAddr + ")");
            ButtonGroup group = new ButtonGroup();
            group.add(fromFuncStart);
            group.add(fromCursor);
            modePanel.add(fromFuncStart);
            modePanel.add(fromCursor);
            JCheckBox allowXref = new JCheckBox("Allow XRef fallback", ALLOW_XREF_FALLBACK);
            allowXref.setToolTipText("If enabled, Sigga may generate a caller/reference-site signature when direct signatures fail.");
            modePanel.add(allowXref);

            // --- Configuration mode selector ---
            JPanel configModePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
            configModePanel.add(new JLabel("Scan profile:  "));
            JRadioButton cfgDefault = new JRadioButton("Default", true);
            JRadioButton cfgCustom = new JRadioButton("Custom");
            ButtonGroup cfgGroup = new ButtonGroup();
            cfgGroup.add(cfgDefault);
            cfgGroup.add(cfgCustom);
            configModePanel.add(cfgDefault);
            configModePanel.add(cfgCustom);

            // --- Configuration panel (hidden by default) ---
            JPanel configPanel = new JPanel(new GridLayout(6, 2, 6, 4));
            configPanel.setBorder(BorderFactory.createTitledBorder("Configuration"));
            configPanel.setVisible(false);

            JSpinner spMaxInstr = new JSpinner(new SpinnerNumberModel(MAX_INSTRUCTIONS_TO_SCAN, 1, 10000, 10));
            JSpinner spMinWindow = new JSpinner(new SpinnerNumberModel(MIN_WINDOW_BYTES, 1, 256, 1));
            JSpinner spMaxWindow = new JSpinner(new SpinnerNumberModel(MAX_WINDOW_BYTES, 1, 1024, 8));
            JSpinner spHeadSpan = new JSpinner(new SpinnerNumberModel(HEAD_CHECK_SPAN, 1, 32, 1));
            JSpinner spXrefCtx = new JSpinner(new SpinnerNumberModel(XREF_CONTEXT_INSTRUCTIONS, 1, 64, 1));
            JSpinner spMaxOffset = new JSpinner(new SpinnerNumberModel(MAX_START_OFFSET, 1, 4096, 8));

            configPanel.add(new JLabel("Max instructions to scan:"));
            configPanel.add(spMaxInstr);
            configPanel.add(new JLabel("Min signature length (bytes):"));
            configPanel.add(spMinWindow);
            configPanel.add(new JLabel("Max signature length (bytes):"));
            configPanel.add(spMaxWindow);
            configPanel.add(new JLabel("Head check span (bytes):"));
            configPanel.add(spHeadSpan);
            configPanel.add(new JLabel("XRef context instructions:"));
            configPanel.add(spXrefCtx);
            configPanel.add(new JLabel("Max start offset (bytes):"));
            configPanel.add(spMaxOffset);

            cfgCustom.addActionListener(e -> { configPanel.setVisible(true); dialog.pack(); });
            cfgDefault.addActionListener(e -> {
                resetConfigurationDefaults();
                spMaxInstr.setValue(MAX_INSTRUCTIONS_TO_SCAN);
                spMinWindow.setValue(MIN_WINDOW_BYTES);
                spMaxWindow.setValue(MAX_WINDOW_BYTES);
                spHeadSpan.setValue(HEAD_CHECK_SPAN);
                spXrefCtx.setValue(XREF_CONTEXT_INSTRUCTIONS);
                spMaxOffset.setValue(MAX_START_OFFSET);
                configPanel.setVisible(false);
                dialog.pack();
            });

            // --- Center: combine mode + config ---
            JPanel centerPanel = new JPanel(new BorderLayout(0, 6));
            centerPanel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));
            centerPanel.add(modePanel, BorderLayout.NORTH);
            JPanel configWrapper = new JPanel(new BorderLayout(0, 4));
            configWrapper.add(configModePanel, BorderLayout.NORTH);
            configWrapper.add(configPanel, BorderLayout.CENTER);
            centerPanel.add(configWrapper, BorderLayout.CENTER);
            dialog.add(centerPanel, BorderLayout.CENTER);

            // --- Buttons panel ---
            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            JButton okBtn = new JButton("Generate");
            JButton cancelBtn = new JButton("Cancel");
            okBtn.addActionListener(e -> {
                selectedMode[0] = fromCursor.isSelected() ? StartMode.CURRENT_ADDRESS : StartMode.FUNCTION_START;
                ALLOW_XREF_FALLBACK = allowXref.isSelected();
                if (cfgDefault.isSelected()) {
                    resetConfigurationDefaults();
                } else {
                    int minW = (int) spMinWindow.getValue();
                    int maxW = (int) spMaxWindow.getValue();
                    if (minW > maxW) {
                        JOptionPane.showMessageDialog(dialog,
                            "Min signature length (" + minW + ") cannot exceed max (" + maxW + ").",
                            "Invalid Configuration", JOptionPane.WARNING_MESSAGE);
                        return;
                    }
                    MAX_INSTRUCTIONS_TO_SCAN = (int) spMaxInstr.getValue();
                    MIN_WINDOW_BYTES = minW;
                    MAX_WINDOW_BYTES = maxW;
                    HEAD_CHECK_SPAN = (int) spHeadSpan.getValue();
                    XREF_CONTEXT_INSTRUCTIONS = (int) spXrefCtx.getValue();
                    MAX_START_OFFSET = (int) spMaxOffset.getValue();
                }
                confirmed[0] = true;
                dialog.dispose();
            });
            cancelBtn.addActionListener(e -> dialog.dispose());
            buttonPanel.add(okBtn);
            buttonPanel.add(cancelBtn);
            dialog.add(buttonPanel, BorderLayout.SOUTH);

            dialog.getRootPane().setDefaultButton(okBtn);
            dialog.pack();
            dialog.setMinimumSize(new Dimension(420, 400));
            dialog.setLocationRelativeTo(null);
            dialog.setVisible(true);
        };

        if (SwingUtilities.isEventDispatchThread()) {
            dialogTask.run();
        } else {
            SwingUtilities.invokeAndWait(dialogTask);
        }

        return confirmed[0] ? selectedMode[0] : null;
    }

    private void generateSignatureRoutine(Function func, Address startAddr) throws Exception {
        uniquenessCache.clear();
        parsedSignatureCache.clear();

        // Snap to the containing instruction boundary so offsets and sigs stay aligned!
        // This also ensures that if the user selects "Current Address" but happens to be in the middle of an instruction, we still generate a valid signature!.
        Instruction startInsn = getInstructionContaining(startAddr);
        if (startInsn == null) {
            printerr("Sigga: No instruction found at " + startAddr);
            return;
        }
        startAddr = startInsn.getMinAddress();

        List<Instruction> instructions = getInstructionsFrom(func.getBody(), startAddr, MAX_INSTRUCTIONS_TO_SCAN);
        
        // --- TIER 1 & 2: DIRECT SCAN ---
        monitor.setMessage("Scanning for Direct Signature...");
        TokenData data = tokenizeInstructions(instructions, MaskProfile.STRICT);
        SigResult directResult = findCheapestSignature(data, startAddr);
        
        if (directResult != null) {
            finish(directResult);
            return;
        }
        
        println("... Direct scan failed. Function is likely generic/duplicate.");

        // --- TIER 3: XREF SCAN ---
        if (ALLOW_XREF_FALLBACK) {
            monitor.setMessage("Checking Tier 3 (XRefs)...");
            SigResult xrefResult = tryXRefSignature(func);
            if (xrefResult != null) {
                finish(xrefResult);
                return;
            }

            println("... Tier 3 failed (No unique XRefs found).");
        } else {
            println("... Tier 3 skipped (XRef fallback disabled).");
        }

        // --- TIER 4: DESPERATION ---
        monitor.setMessage("Checking Tier 4 (Minimal)...");
        TokenData looseData = tokenizeInstructions(instructions, MaskProfile.MINIMAL);
        SigResult looseResult = findCheapestSignature(looseData, startAddr);
        
        if (looseResult != null) {
            looseResult.tier = "Tier 4 (Low Confidence / Desperation)";
            looseResult.quality = Math.min(looseResult.quality, 60);
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
        println("Heuristic confidence: " + result.quality + "/100");
        if (result.resolver != null) {
            println("Resolver:   " + result.resolver);
        }
        println("==================================================");

        copyToClipboard(result.signature);
        println(">> Copied to clipboard.");
    }

    /**
     * Finds the best direct signature: shortest first, then denser concrete bytes, then lower offset.
     */
    private SigResult findCheapestSignature(TokenData data, Address startAddr) throws CancelledException {
        List<String> tokens = data.tokens;
        int n = tokens.size();
        SigResult best = null;

        for (int i = 0; i < n; i++) {
            monitor.checkCancelled();

            if (!data.instructionStartIndices.contains(i)) continue;
            if (i >= MAX_START_OFFSET) break;
            // Runtime scanners commonly reject leading wildcards; do not emit them.
            if (tokens.get(i).contains("?")) continue;

            StringBuilder sigBuilder = new StringBuilder();
            int byteCount = 0;

            for (int j = i; j < n; j++) {
                String tok = tokens.get(j);
                if (sigBuilder.length() > 0) sigBuilder.append(" ");
                sigBuilder.append(tok);
                byteCount++;

                boolean isInstructionEnd = (j + 1 == n) || data.instructionStartIndices.contains(j + 1);
                if (!isInstructionEnd) continue;
                if (byteCount < MIN_WINDOW_BYTES) continue;

                String currentSig = sigBuilder.toString();
                String finalSig = trimTrailingWildcards(currentSig);
                int finalLength = countSignatureTokens(finalSig);
                if (finalLength < MIN_WINDOW_BYTES) continue;
                if (finalLength > MAX_WINDOW_BYTES) break;

                int bestLength = best == null ? Integer.MAX_VALUE : countSignatureTokens(best.signature);
                if (finalLength > bestLength) break;

                boolean weakHead = isHeadWeak(tokens, i);
                String tier = weakHead ? "Tier 2 (Direct / Loose Head)" : "Tier 1 (Direct / Strong Head)";
                if (isSignatureUnique(finalSig)) {
                    SigResult candidate = new SigResult(finalSig, startAddr, i,
                        calculateHeuristicConfidence(finalSig, weakHead), tier);
                    if (isBetterDirectCandidate(candidate, best)) best = candidate;
                }

                // Future trailing wildcards cannot change this emitted pattern. A future concrete
                // byte can only make it longer, so it cannot beat an equal-or-shorter best.
                bestLength = best == null ? Integer.MAX_VALUE : countSignatureTokens(best.signature);
                if (finalLength >= bestLength) break;
                if (byteCount > MAX_WINDOW_BYTES) break;
            }
        }
        return best;
    }

    private boolean isBetterDirectCandidate(SigResult candidate, SigResult current) {
        if (current == null) return true;

        int candidateLength = countSignatureTokens(candidate.signature);
        int currentLength = countSignatureTokens(current.signature);
        if (candidateLength != currentLength) return candidateLength < currentLength;

        int candidateConcrete = countConcreteTokens(candidate.signature);
        int currentConcrete = countConcreteTokens(current.signature);
        if (candidateConcrete != currentConcrete) return candidateConcrete > currentConcrete;

        return candidate.offset < current.offset;
    }

    private int calculateHeuristicConfidence(String signature, boolean weakHead) {
        int total = countSignatureTokens(signature);
        if (total == 0) return 0;

        int density = (countConcreteTokens(signature) * 100) / total;
        int confidence = 60 + (density * 40) / 100;
        return weakHead ? Math.max(50, confidence - 10) : confidence;
    }

    private int countSignatureTokens(String signature) {
        return signature.isEmpty() ? 0 : signature.split(" ").length;
    }

    private int countConcreteTokens(String signature) {
        int concrete = 0;
        for (String token : signature.split(" ")) {
            if (!token.contains("?")) concrete++;
        }
        return concrete;
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
                // 4. Aggressively mask operands that reference mapped code/data or external symbols
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
            int len = getRelocationMaskLength(r);
            for (int i = 0; i < len && (offset + i) < tokens.length; i++) {
                tokens[offset + i] = "?";
            }
        }
    }

    private int getRelocationMaskLength(Relocation r) {
        int len = r.getLength();
        return len > 0 ? len : 4;
    }

    private void maskBranches(Instruction insn, String[] tokens) {
        if (!insn.getFlowType().isCall() && !insn.getFlowType().isJump()) return;

        byte[] bytes;
        try { bytes = insn.getBytes(); } catch (Exception e) { return; }
        int opcodeOffset = getX86OpcodeOffset(bytes);
        if (opcodeOffset >= tokens.length || tokens[opcodeOffset].contains("?")) return;

        int opcode = bytes[opcodeOffset] & 0xff;
        if (opcode == 0xE8 || opcode == 0xE9) {
            maskRange(tokens, opcodeOffset + 1, tokens.length - opcodeOffset - 1);
        }
        // rel8 branches: JMP, Jcc, LOOP*, and JCXZ/JECXZ/JRCXZ.
        else if (opcodeOffset + 1 < tokens.length &&
                 (opcode == 0xEB || (opcode & 0xF0) == 0x70 ||
                  (opcode >= 0xE0 && opcode <= 0xE3))) {
            maskRange(tokens, opcodeOffset + 1, 1);
        }
        // rel16/rel32 conditional branches.
        else if (opcode == 0x0F && opcodeOffset + 1 < tokens.length &&
                 (bytes[opcodeOffset + 1] & 0xF0) == 0x80) {
            maskRange(tokens, opcodeOffset + 2, tokens.length - opcodeOffset - 2);
        }
        // x64 RIP-relative indirect CALL/JMP; x86 absolute-IAT form uses same displacement field.
        else if (opcode == 0xFF && opcodeOffset + 5 < tokens.length) {
            int modrm = bytes[opcodeOffset + 1] & 0xff;
            if (modrm == 0x15 || modrm == 0x25) {
                maskRange(tokens, opcodeOffset + 2, 4);
            }
        }
    }

    private int getX86OpcodeOffset(byte[] bytes) {
        int index = 0;
        while (index < bytes.length) {
            int value = bytes[index] & 0xff;
            boolean legacyPrefix = value == 0xF0 || value == 0xF2 || value == 0xF3 ||
                value == 0x2E || value == 0x36 || value == 0x3E || value == 0x26 ||
                value == 0x64 || value == 0x65 || value == 0x66 || value == 0x67;
            boolean rexPrefix = currentProgram.getDefaultPointerSize() == 8 &&
                value >= 0x40 && value <= 0x4F;
            if (!legacyPrefix && !rexPrefix) break;
            index++;
        }
        return index;
    }

    /**
     * The "Paranoid" masking logic.
     * Identifies operands that point to mapped memory or external symbols and masks their byte representation.
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
                if (block != null) { shouldMask = true; break; }
            }

            if (!shouldMask) {
                Object[] opObjects = insn.getOpObjects(op);
                for (Object obj : opObjects) {
                    if (obj instanceof Scalar) {
                        Scalar s = (Scalar) obj;
                        long val = s.getUnsignedValue();
                        Address possibleAddr = getDefaultAddress(val);
                        if (possibleAddr == null) continue;
                        MemoryBlock block = getMemoryBlock(possibleAddr);
                        if (block != null) shouldMask = true;
                    }
                }
            }

            if (shouldMask) {
                byte[] operandMask = getOperandValueMask(insn, op, bytes.length);
                for (Reference ref : refs) {
                    Address toAddr = ref.getToAddress();
                    if (toAddr != null) {
                        long target = toAddr.getOffset();
                        long instrEnd = insn.getAddress().add(bytes.length).getOffset();
                        if (currentProgram.getDefaultPointerSize() == 8) {
                            // x64 normally reaches mapped operands through RIP-relative disp32.
                            if (!maskOperandEncoding(tokens, bytes, operandMask,
                                    target - instrEnd, 4)) {
                                if (!maskOperandEncoding(tokens, bytes, operandMask, target, 4)) {
                                    maskOperandEncoding(tokens, bytes, operandMask, target, 8);
                                }
                            }
                        } else {
                            // x86 normally encodes mapped operands as absolute disp32.
                            if (!maskOperandEncoding(tokens, bytes, operandMask, target, 4)) {
                                maskOperandEncoding(tokens, bytes, operandMask,
                                    target - instrEnd, 4);
                            }
                        }
                    }
                }

                Object[] opObjects = insn.getOpObjects(op);
                for (Object obj : opObjects) {
                    if (obj instanceof Scalar) {
                        long val = ((Scalar)obj).getUnsignedValue();
                        maskOperandEncoding(tokens, bytes, operandMask, val, 4);
                        if (currentProgram.getDefaultPointerSize() == 8) {
                            maskOperandEncoding(tokens, bytes, operandMask, val, 8);
                        }
                    }
                }
            }
        }
    }

    private byte[] getOperandValueMask(Instruction insn, int operandIndex, int instructionLength) {
        try {
            Mask mask = insn.getPrototype().getOperandValueMask(operandIndex);
            if (mask == null) return null;
            byte[] maskBytes = mask.getBytes();
            return maskBytes.length == instructionLength ? maskBytes : null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Masks a value only where Ghidra says the selected operand stores full value bytes.
     * If no compatible operand mask exists, use the conservative tail fallback below.
     */
    private boolean maskOperandEncoding(String[] tokens, byte[] bytes, byte[] operandMask,
                                        long value, int size) {
        if (operandMask == null) return maskValueNearOperandTail(tokens, bytes, value, size);
        if (size > 8 || bytes.length < size) return false;

        int matchStart = -1;
        int matchCount = 0;
        for (int i = 0; i <= bytes.length - size; i++) {
            boolean fullValueBytes = true;
            for (int k = 0; k < size; k++) {
                if ((operandMask[i + k] & 0xff) != 0xff) {
                    fullValueBytes = false;
                    break;
                }
            }
            if (!fullValueBytes || !matchesLittleEndianValue(bytes, i, value, size)) continue;
            matchStart = i;
            matchCount++;
        }

        if (matchCount != 1) return false;
        maskRange(tokens, matchStart, size);
        return true;
    }

    /**
     * Masks a little-endian immediate/displacement only at the tail of an x86/x64 instruction.
     * A displacement can precede a trailing imm8/imm32, so search at most four bytes before its end.
     */
    private boolean maskValueNearOperandTail(String[] tokens, byte[] bytes, long value, int size) {
        if (size > 8 || bytes.length < size) return false;
        int lastStart = bytes.length - size;
        int firstStart = Math.max(0, lastStart - 4);
        int matchStart = -1;
        int matchCount = 0;
        for (int i = lastStart; i >= firstStart; i--) {
            if (!matchesLittleEndianValue(bytes, i, value, size)) continue;
            matchStart = i;
            matchCount++;
        }
        if (matchCount != 1) return false;
        maskRange(tokens, matchStart, size);
        return true;
    }

    private boolean matchesLittleEndianValue(byte[] bytes, int start, long value, int size) {
        long currentValue = 0;
        for (int k = 0; k < size; k++) {
            currentValue |= ((long) (bytes[start + k] & 0xff)) << (k * 8);
        }
        return size == 4 ? (int) currentValue == (int) value : currentValue == value;
    }

    private void maskRange(String[] tokens, int start, int len) {
        for (int i = 0; i < len && (start + i) < tokens.length; i++) {
            tokens[start + i] = "?";
        }
    }

    // ============================================================================================
    //  XREF FALLBACK LOGIC
    // ============================================================================================

    private SigResult tryXRefSignature(Function targetFunc) throws Exception {
        Address funcStart = targetFunc.getEntryPoint();
        Reference[] refs = getReferencesTo(funcStart);
        XRefCandidate best = null;
        
        for (Reference ref : refs) {
            monitor.checkCancelled();
            Instruction referenceInsn = getInstructionContaining(ref.getFromAddress());
            if (referenceInsn == null) continue;

            XRefResolver resolver = getSupportedXRefResolver(referenceInsn, ref);
            if (resolver == null) continue;

            Function callerFunc = getFunctionContaining(referenceInsn.getMinAddress());
            if (callerFunc == null) continue;

            List<Instruction> context = buildXRefContext(referenceInsn, callerFunc);
            if (context.isEmpty()) continue;

            int referenceIndex = indexOfInstruction(context, referenceInsn);
            if (referenceIndex < 0) continue;

            XRefCandidate candidate = findBestXRefCandidate(
                context, referenceIndex, resolver, ref.getFromAddress());
            if (isBetterXRefCandidate(candidate, best)) best = candidate;
        }
        return best == null ? null : best.result;
    }

    private XRefCandidate findBestXRefCandidate(List<Instruction> context, int referenceIndex,
                                                 XRefResolver resolver, Address referenceAddress)
            throws Exception {
        TokenData data = tokenizeInstructions(context, MaskProfile.STRICT);
        int[] instructionOffsets = new int[context.size() + 1];
        for (int i = 0; i < context.size(); i++) {
            instructionOffsets[i + 1] = instructionOffsets[i] + context.get(i).getLength();
        }

        XRefCandidate best = null;
        for (int startIndex = 0; startIndex <= referenceIndex; startIndex++) {
            monitor.checkCancelled();
            int startToken = instructionOffsets[startIndex];
            if (data.tokens.get(startToken).contains("?")) continue;

            for (int endIndex = referenceIndex; endIndex < context.size(); endIndex++) {
                int endToken = instructionOffsets[endIndex + 1];
                int rawLength = endToken - startToken;
                if (rawLength < MIN_WINDOW_BYTES) continue;

                String rawSignature = joinTokens(data.tokens, startToken, endToken);
                String finalSignature = trimTrailingWildcards(rawSignature);
                int finalLength = countSignatureTokens(finalSignature);
                if (finalLength < MIN_WINDOW_BYTES) continue;
                if (finalLength > MAX_WINDOW_BYTES) break;

                int bestLength = best == null ? Integer.MAX_VALUE :
                    countSignatureTokens(best.result.signature);
                if (finalLength > bestLength) break;

                if (isSignatureUnique(finalSignature)) {
                    boolean weakHead = isHeadWeak(data.tokens, startToken);
                    XRefResolver adjustedResolver = copyXRefResolver(resolver);
                    adjustedResolver.instructionOffset = instructionOffsets[referenceIndex] - startToken;
                    SigResult result = new SigResult(finalSignature,
                        context.get(startIndex).getMinAddress(), 0,
                        calculateHeuristicConfidence(finalSignature, weakHead),
                        "Tier 3 (XRef / " + adjustedResolver.kind + ")",
                        formatXRefResolver(adjustedResolver));
                    XRefCandidate candidate = new XRefCandidate(result, weakHead, referenceAddress);
                    if (isBetterXRefCandidate(candidate, best)) best = candidate;
                }

                bestLength = best == null ? Integer.MAX_VALUE :
                    countSignatureTokens(best.result.signature);
                if (finalLength >= bestLength || rawLength > MAX_WINDOW_BYTES) break;
            }
        }
        return best;
    }

    private boolean isBetterXRefCandidate(XRefCandidate candidate, XRefCandidate current) {
        if (candidate == null) return false;
        if (current == null) return true;

        int candidateLength = countSignatureTokens(candidate.result.signature);
        int currentLength = countSignatureTokens(current.result.signature);
        if (candidateLength != currentLength) return candidateLength < currentLength;
        if (candidate.weakHead != current.weakHead) return !candidate.weakHead;

        int candidateConcrete = countConcreteTokens(candidate.result.signature);
        int currentConcrete = countConcreteTokens(current.result.signature);
        if (candidateConcrete != currentConcrete) return candidateConcrete > currentConcrete;

        int referenceOrder = candidate.referenceAddress.compareTo(current.referenceAddress);
        if (referenceOrder != 0) return referenceOrder < 0;
        return candidate.result.address.compareTo(current.result.address) < 0;
    }

    private String joinTokens(List<String> tokens, int start, int endExclusive) {
        StringBuilder builder = new StringBuilder();
        for (int i = start; i < endExclusive; i++) {
            if (builder.length() > 0) builder.append(' ');
            builder.append(tokens.get(i));
        }
        return builder.toString();
    }

    private XRefResolver copyXRefResolver(XRefResolver resolver) {
        return new XRefResolver(resolver.kind, resolver.displacementOffset,
            resolver.displacementSize, resolver.instructionLength);
    }

    private XRefResolver getSupportedXRefResolver(Instruction insn, Reference ref) {
        byte[] bytes;
        try { bytes = insn.getBytes(); } catch (Exception e) { return null; }
        int opcodeOffset = getX86OpcodeOffset(bytes);
        if (opcodeOffset >= bytes.length) return null;

        int opcode = bytes[opcodeOffset] & 0xff;
        if (opcode == 0xE8 && ref.getReferenceType().isCall()) {
            int displacementSize = bytes.length - opcodeOffset - 1;
            if (displacementSize == 2 || displacementSize == 4) {
                return new XRefResolver("rel" + (displacementSize * 8) + "-call",
                    opcodeOffset + 1, displacementSize, bytes.length);
            }
        }
        if (opcode == 0xE9 && ref.getReferenceType().isJump()) {
            int displacementSize = bytes.length - opcodeOffset - 1;
            if (displacementSize == 2 || displacementSize == 4) {
                return new XRefResolver("rel" + (displacementSize * 8) + "-jmp",
                    opcodeOffset + 1, displacementSize, bytes.length);
            }
        }
        if (opcode == 0xEB && ref.getReferenceType().isJump() &&
            bytes.length - opcodeOffset - 1 == 1) {
            return new XRefResolver("rel8-jmp", opcodeOffset + 1, 1, bytes.length);
        }
        if (currentProgram.getDefaultPointerSize() == 8 && opcode == 0x8D &&
            ref.getReferenceType().isData() && opcodeOffset + 6 <= bytes.length) {
            int modrm = bytes[opcodeOffset + 1] & 0xff;
            if ((modrm & 0xC7) == 0x05) {
                return new XRefResolver("rip-rel-lea", opcodeOffset + 2, 4, bytes.length);
            }
        }
        return null;
    }

    private List<Instruction> buildXRefContext(Instruction referenceInsn, Function callerFunc) {
        List<Instruction> context = new ArrayList<>();
        context.add(referenceInsn);

        Instruction current = referenceInsn;
        int beforeBytes = referenceInsn.getLength();
        for (int count = 0; count < XREF_CONTEXT_INSTRUCTIONS; count++) {
            Instruction previous = currentProgram.getListing()
                .getInstructionBefore(current.getMinAddress());
            if (previous == null || !callerFunc.getBody().contains(previous.getMinAddress())) break;
            Address fallThrough = previous.getFallThrough();
            if (fallThrough == null || !fallThrough.equals(current.getMinAddress())) break;
            if (beforeBytes + previous.getLength() >
                MAX_WINDOW_BYTES + MAX_X86_INSTRUCTION_BYTES) break;
            context.add(0, previous);
            beforeBytes += previous.getLength();
            current = previous;
        }

        current = referenceInsn;
        int afterBytes = referenceInsn.getLength();
        for (int count = 0; count < XREF_CONTEXT_INSTRUCTIONS; count++) {
            if (!current.getFlowType().hasFallthrough()) break;
            Instruction next = current.getNext();
            Address fallThrough = current.getFallThrough();
            if (next == null || fallThrough == null ||
                !fallThrough.equals(next.getMinAddress()) ||
                !callerFunc.getBody().contains(next.getMinAddress())) break;
            if (afterBytes + next.getLength() >
                MAX_WINDOW_BYTES + MAX_X86_INSTRUCTION_BYTES) break;
            context.add(next);
            afterBytes += next.getLength();
            current = next;
        }

        return context;
    }

    private int indexOfInstruction(List<Instruction> context, Instruction target) {
        for (int i = 0; i < context.size(); i++) {
            if (context.get(i).getMinAddress().equals(target.getMinAddress())) return i;
        }
        return -1;
    }

    private String formatXRefResolver(XRefResolver resolver) {
        int displacementAt = resolver.instructionOffset + resolver.displacementOffset;
        int nextInstruction = resolver.instructionOffset + resolver.instructionLength;
        return String.format("%s: target = match + 0x%X + signed read_i%d(match + 0x%X)",
            resolver.kind, nextInstruction, resolver.displacementSize * 8, displacementAt);
    }

    // ============================================================================================
    //  UTILITIES
    // ============================================================================================

    private boolean isSignatureUnique(String sigStr) throws CancelledException {
        Boolean cached = uniquenessCache.get(sigStr);
        if (cached != null) return cached;

        try {
            monitor.checkCancelled();
            ByteSignature sig = parsedSignatureCache.get(sigStr);
            if (sig == null) {
                sig = new ByteSignature(sigStr);
                parsedSignatureCache.put(sigStr, sig);
            }
            ConcreteAnchor anchor = getLongestConcreteAnchor(sig);
            if (anchor != null) {
                Boolean anchorResult = determineUniquenessFromAnchor(sig, anchor);
                if (anchorResult != null) {
                    uniquenessCache.put(sigStr, anchorResult);
                    return anchorResult;
                }
            }

            boolean unique = determineUniquenessWithMaskedSearch(sig);
            uniquenessCache.put(sigStr, unique);
            return unique;
        } catch (CancelledException e) {
            throw e;
        } catch (Exception e) {
            uniquenessCache.put(sigStr, false);
            return false;
        }
    }

    /**
     * Enumerates exact anchor matches and verifies the full masked pattern at each derived start.
     * Returns null after the safety cap so callers can fall back to native masked searching.
     */
    private Boolean determineUniquenessFromAnchor(ByteSignature sig, ConcreteAnchor anchor)
            throws CancelledException {
        Address searchFrom = null;
        int verifiedMatches = 0;

        for (int examined = 0; examined < MAX_ANCHOR_MATCHES_TO_VERIFY; examined++) {
            monitor.checkCancelled();
            Address anchorMatch = findInExecutableMemory(anchor.signature, searchFrom);
            if (anchorMatch == null) return verifiedMatches == 1;

            try {
                Address candidateStart = anchorMatch.subtract(anchor.offset);
                if (matchesSignatureAt(candidateStart, sig)) {
                    verifiedMatches++;
                    if (verifiedMatches > 1) return false;
                }
                searchFrom = anchorMatch.add(1);
            } catch (Exception e) {
                return null;
            }
        }
        return null;
    }

    private boolean determineUniquenessWithMaskedSearch(ByteSignature sig)
            throws CancelledException {
        Address firstMatch = findInExecutableMemory(sig, null);
        if (firstMatch == null) return false;
        try {
            return findInExecutableMemory(sig, firstMatch.add(1)) == null;
        } catch (Exception e) {
            return true;
        }
    }

    private ConcreteAnchor getLongestConcreteAnchor(ByteSignature sig) {
        int bestStart = -1;
        int bestLength = 0;
        int runStart = 0;
        int runLength = 0;

        for (int i = 0; i < sig.mask.length; i++) {
            if ((sig.mask[i] & 0xff) == 0xff) {
                if (runLength == 0) runStart = i;
                runLength++;
                if (runLength > bestLength) {
                    bestStart = runStart;
                    bestLength = runLength;
                }
            } else {
                runLength = 0;
            }
        }

        if (bestLength < MIN_CONCRETE_ANCHOR_BYTES) return null;
        byte[] bytes = Arrays.copyOfRange(sig.bytes, bestStart, bestStart + bestLength);
        byte[] mask = new byte[bestLength];
        Arrays.fill(mask, (byte) 0xff);
        return new ConcreteAnchor(new ByteSignature(bytes, mask), bestStart);
    }

    private boolean matchesSignatureAt(Address start, ByteSignature sig) {
        try {
            Memory mem = currentProgram.getMemory();
            MemoryBlock block = mem.getBlock(start);
            if (block == null || !block.isExecute()) return false;

            Address end = start.add(sig.bytes.length - 1);
            if (end.compareTo(block.getEnd()) > 0) return false;

            byte[] actual = new byte[sig.bytes.length];
            mem.getBytes(start, actual);
            for (int i = 0; i < actual.length; i++) {
                if ((sig.mask[i] & 0xff) == 0xff && actual[i] != sig.bytes[i]) return false;
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isSupportedX86Program() {
        Processor x86 = Processor.findOrPossiblyCreateProcessor("x86");
        int pointerSize = currentProgram.getDefaultPointerSize();
        return currentProgram.getLanguage().getProcessor().equals(x86) &&
               (pointerSize == 4 || pointerSize == 8);
    }

    private void resetConfigurationDefaults() {
        MAX_INSTRUCTIONS_TO_SCAN = DEFAULT_MAX_INSTRUCTIONS_TO_SCAN;
        MIN_WINDOW_BYTES = DEFAULT_MIN_WINDOW_BYTES;
        MAX_WINDOW_BYTES = DEFAULT_MAX_WINDOW_BYTES;
        HEAD_CHECK_SPAN = DEFAULT_HEAD_CHECK_SPAN;
        XREF_CONTEXT_INSTRUCTIONS = DEFAULT_XREF_CONTEXT_INSTRUCTIONS;
        MAX_START_OFFSET = DEFAULT_MAX_START_OFFSET;
    }

    private Address getDefaultAddress(long offset) {
        try {
            return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        } catch (Exception e) {
            return null;
        }
    }

    private Address findInExecutableMemory(ByteSignature sig, Address minAddr) throws CancelledException {
        Memory mem = currentProgram.getMemory();
        for (MemoryBlock block : mem.getBlocks()) {
            monitor.checkCancelled();
            if (!block.isExecute()) continue;

            Address start = block.getStart();
            Address end = block.getEnd();
            if (minAddr != null) {
                if (end.compareTo(minAddr) < 0) continue;
                if (start.compareTo(minAddr) < 0) start = minAddr;
            }

            Address match = mem.findBytes(start, end, sig.bytes, sig.mask, true, monitor);
            if (match != null) return match;
        }
        return null;
    }
    
    private List<Instruction> getInstructionsFrom(AddressSetView body, Address startAddr, int max) {
        List<Instruction> list = new ArrayList<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(startAddr, true);
        int count = 0;
        while (it.hasNext() && count < max) {
            Instruction insn = it.next();
            if (!body.contains(insn.getMinAddress())) break;
            list.add(insn);
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

        public ByteSignature(byte[] bytes, byte[] mask) {
            this.bytes = bytes;
            this.mask = mask;
        }
    }

    private static class ConcreteAnchor {
        ByteSignature signature;
        int offset;

        ConcreteAnchor(ByteSignature signature, int offset) {
            this.signature = signature;
            this.offset = offset;
        }
    }
}
