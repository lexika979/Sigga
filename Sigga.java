// Sigga-X: A definitive Ghidra Signature Maker with XRef Scanning
// @author lexika, Krixx
// @category Functions
// @keybinding
// @menupath
// @toolbar

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

public class SiggaX extends GhidraScript {

    // --- CONFIGURATION ---
    private static final int MAX_INSTRUCTIONS_TO_SCAN = 256;
    private static final int MIN_WINDOW_BYTES = 16;
    private static final int MAX_WINDOW_BYTES = 64;
    private static final int WINDOW_STEP_BYTES = 8;
    private static final int XREF_SIG_INSTRUCTIONS = 8; // How many instructions to use for an XRef signature.
    
    private static class ByteSignature {
        public byte[] bytes;
        public byte[] mask;
        public ByteSignature(String s){String c=s.replaceAll("\\s","");if(c.isEmpty()){throw new IllegalArgumentException("Sig empty");}List<Byte> b=new LinkedList<>();List<Byte> m=new LinkedList<>();for(int i=0;i<c.length();){if(c.charAt(i)=='?'){b.add((byte)0);m.add((byte)0);i++;continue;}try{byte v=(byte)Integer.parseInt(c.substring(i,i+2),16);b.add(v);m.add((byte)0xFF);i+=2;}catch(Exception e){throw new IllegalArgumentException("Invalid hex/wildcard",e);}}this.bytes=toByteArray(b);this.mask=toByteArray(m);}
        private byte[] toByteArray(List<Byte> l){byte[] a=new byte[l.size()];for(int i=0;i<l.size();i++)a[i]=l.get(i);return a;}
    }

    @Override
    public void run() throws Exception {
        String action = askChoice("Sigga-X", "Choose an action:", Arrays.asList("Create Signature", "Find Signature"), "Create Signature");
        if ("Create Signature".equals(action)) createSignature();
        else if ("Find Signature".equals(action)) findSignature();
    }
    
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
            for (int windowSize = MIN_WINDOW_BYTES; windowSize <= MAX_WINDOW_BYTES; windowSize += WINDOW_STEP_BYTES) {
                monitor.checkCancelled();
                monitor.setMessage(String.format("Sigga-X: Searching with window size %d...", windowSize));
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
        
        println("Phase 1 failed. Proceeding to Phase 2: Signature by Cross-Reference (XRef).");
        tryXRefSignature(function);
    }
    
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
    
    private List<String> buildFeatureVector(Function function, int limit) throws MemoryAccessException {
        List<String> tokens = new LinkedList<>();
        InstructionIterator iter = currentProgram.getListing().getInstructions(function.getBody(), true);
        while (iter.hasNext() && tokens.size() < (limit * 16)) {
            tokens.addAll(instructionToTokens(iter.next()));
        }
        return tokens;
    }
    
    private String buildFeatureString(List<Instruction> instructions) throws MemoryAccessException {
        List<String> tokens = new LinkedList<>();
        for (Instruction i : instructions) {
            tokens.addAll(instructionToTokens(i));
        }
        return String.join(" ", tokens);
    }

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

    private boolean isSignatureUniqueInBinary(String signature) throws CancelledException {
        if (signature.isEmpty()) return false;
        ByteSignature sig = new ByteSignature(signature);
        Memory mem = currentProgram.getMemory();
        Address firstMatch = mem.findBytes(currentProgram.getMinAddress(), sig.bytes, sig.mask, true, monitor);
        if (firstMatch == null) return false;
        Address secondMatch = mem.findBytes(firstMatch.add(1), sig.bytes, sig.mask, true, monitor);
        return (secondMatch == null);
    }
    
    private void findSignature() {
        try {
            String signature = askString("Find Signature", "Enter signature:");
            ByteSignature sig = new ByteSignature(signature);
            Address found = currentProgram.getMemory().findBytes(currentProgram.getMinAddress(), sig.bytes, sig.mask, true, monitor);
            if (found == null) println("Signature not found.");
            else { println("Signature found at: " + found); goTo(found); }
        } catch (Exception e) {
            printerr("Error: " + e.getMessage());
        }
    }

    private void copyToClipboard(String text) {
        try {
            Clipboard c = Toolkit.getDefaultToolkit().getSystemClipboard();
            c.setContents(new StringSelection(text), null);
        } catch (Exception e) {
            printerr("Warning: Could not copy to clipboard. " + e.getMessage());
        }
    }
}