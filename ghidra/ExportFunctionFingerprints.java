// Ghidra post-script. Exports deterministic function fingerprints as JSONL.
// Environment:
//   REREVVED_DUMP_PATH output path
//@category ReRevved

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.exception.CancelledException;

public class ExportFunctionFingerprints extends GhidraScript {
    private static final long SMALL_SCALAR_LIMIT = 0x100;
    private static final int MAX_STRING_ANCHOR_LENGTH = 256;

    @Override
    public void run() throws Exception {
        String outPath = requireEnv("REREVVED_DUMP_PATH");
        List<Function> functions = collectFunctions(currentProgram.getFunctionManager());
        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(outPath), StandardCharsets.UTF_8))) {
            out.print("{\"recordType\":\"program\",\"program\":");
            out.print(jsonQuote(currentProgram.getName()));
            out.print(",\"imageBase\":");
            out.print(jsonQuote(formatAddress(analysisImageBase())));
            out.print(",\"language\":");
            out.print(jsonQuote(currentProgram.getLanguageID().toString()));
            out.print(",\"imageSha256\":");
            String imageSha256 = currentProgram.getExecutableSHA256();
            out.print(imageSha256 == null ? "null" : jsonQuote(imageSha256.toUpperCase()));
            out.print(",\"source\":\"ghidra\",\"fingerprintAlgorithm\":\"ghidra-instruction-v1\"");
            out.println(",\"functionCount\":" + functions.size() + "}");
            for (Function function : functions) {
                monitor.checkCancelled();
                Fingerprint fingerprint = fingerprint(function);
                writeFunction(out, function, fingerprint);
            }
            out.flush();
            if (out.checkError()) {
                throw new IOException("failed while writing fingerprint export: " + outPath);
            }
        }
        println("WROTE: " + outPath);
    }

    private List<Function> collectFunctions(FunctionManager manager) throws CancelledException {
        List<Function> functions = new ArrayList<>();
        FunctionIterator iterator = manager.getFunctions(true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Function function = iterator.next();
            if (!function.isExternal()) {
                functions.add(function);
            }
        }
        Collections.sort(functions, new Comparator<Function>() {
            @Override
            public int compare(Function first, Function second) {
                int addressOrder = first.getEntryPoint().compareTo(second.getEntryPoint());
                if (addressOrder != 0) {
                    return addressOrder;
                }
                return first.getName().compareTo(second.getName());
            }
        });
        return functions;
    }

    private Fingerprint fingerprint(Function function) throws Exception {
        MessageDigest exact = sha256();
        MessageDigest shape = sha256();
        MessageDigest mnemonic = sha256();
        Listing listing = currentProgram.getListing();
        ReferenceManager references = currentProgram.getReferenceManager();
        InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
        Set<String> stringAnchors = new TreeSet<>();
        int instructionCount = 0;
        int directCallCount = 0;

        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = iterator.next();
            exact.update(instruction.getBytes());
            updateUtf8(shape, shapeInstruction(instruction));
            updateUtf8(mnemonic, instruction.getMnemonicString() + "\n");
            instructionCount++;

            FlowType flowType = instruction.getFlowType();
            if (flowType != null && flowType.isCall() && !flowType.isComputed()) {
                directCallCount++;
            }
            collectStringAnchors(listing, references, instruction, stringAnchors);
        }
        monitor.checkCancelled();
        return new Fingerprint(hex(exact.digest()), hex(shape.digest()),
            hex(mnemonic.digest()), instructionCount, directCallCount, stringAnchors,
            function.getBody().getNumAddresses());
    }

    private void collectStringAnchors(Listing listing, ReferenceManager references,
            Instruction instruction, Set<String> stringAnchors) {
        for (Reference reference : references.getReferencesFrom(instruction.getAddress())) {
            Data data = listing.getDefinedDataContaining(reference.getToAddress());
            if (data == null || !data.hasStringValue()) {
                continue;
            }
            Object value = data.getValue();
            if (value instanceof String) {
                stringAnchors.add(capStringAnchor((String) value));
            }
        }
    }

    private String capStringAnchor(String value) {
        return value.length() <= MAX_STRING_ANCHOR_LENGTH ? value :
            value.substring(0, MAX_STRING_ANCHOR_LENGTH);
    }

    private String shapeInstruction(Instruction instruction) {
        StringBuilder shape = new StringBuilder(instruction.getMnemonicString());
        for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
            shape.append('|');
            for (Object object : instruction.getOpObjects(operand)) {
                shape.append(shapeObject(object)).append(';');
            }
        }
        shape.append('\n');
        return shape.toString();
    }

    private String shapeObject(Object object) {
        if (object instanceof Address) {
            return "<ADDRESS>";
        }
        if (object instanceof Scalar) {
            Scalar scalar = (Scalar) object;
            long value = scalar.getSignedValue();
            if (value >= -SMALL_SCALAR_LIMIT && value <= SMALL_SCALAR_LIMIT) {
                return "SCALAR(" + value + ')';
            }
            return "<SCALAR>";
        }
        return object == null ? "<NULL>" : object.toString();
    }

    private void writeFunction(PrintWriter out, Function function, Fingerprint fingerprint) {
        out.print("{\"recordType\":\"function\",\"address\":");
        out.print(jsonQuote(formatAddress(function.getEntryPoint())));
        out.print(",\"minAddress\":");
        out.print(jsonQuote(formatAddress(function.getBody().getMinAddress())));
        out.print(",\"maxAddress\":");
        out.print(jsonQuote(formatAddress(function.getBody().getMaxAddress())));
        out.print(",\"name\":");
        out.print(jsonQuote(function.getName()));
        out.print(",\"bodySize\":");
        out.print(fingerprint.bodySize);
        out.print(",\"instructionCount\":");
        out.print(fingerprint.instructionCount);
        out.print(",\"exactHash\":");
        out.print(jsonQuote(fingerprint.exactHash));
        out.print(",\"shapeHash\":");
        out.print(jsonQuote(fingerprint.shapeHash));
        out.print(",\"mnemonicHash\":");
        out.print(jsonQuote(fingerprint.mnemonicHash));
        out.print(",\"directCallCount\":");
        out.print(fingerprint.directCallCount);
        out.print(",\"stringAnchors\":[");
        boolean first = true;
        for (String anchor : fingerprint.stringAnchors) {
            if (!first) {
                out.print(',');
            }
            out.print(jsonQuote(anchor));
            first = false;
        }
        out.println("]}");
    }

    private String formatAddress(Address address) {
        int digits = (address.getAddressSpace().getSize() + 3) / 4;
        return String.format("0x%0" + digits + "X", address.getOffset());
    }

    private Address analysisImageBase() {
        MemoryBlock image = currentProgram.getMemory().getBlock("image");
        return image == null ? currentProgram.getMemory().getMinAddress() : image.getStart();
    }

    private MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private void updateUtf8(MessageDigest digest, String value) {
        digest.update(value.getBytes(StandardCharsets.UTF_8));
    }

    private String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            result.append(String.format("%02x", value & 0xff));
        }
        return result.toString();
    }

    private String jsonQuote(String value) {
        StringBuilder result = new StringBuilder(value.length() + 2);
        result.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"': result.append("\\\""); break;
                case '\\': result.append("\\\\"); break;
                case '\b': result.append("\\b"); break;
                case '\f': result.append("\\f"); break;
                case '\n': result.append("\\n"); break;
                case '\r': result.append("\\r"); break;
                case '\t': result.append("\\t"); break;
                default:
                    if (character < 0x20) {
                        result.append(String.format("\\u%04x", (int) character));
                    }
                    else {
                        result.append(character);
                    }
                    break;
            }
        }
        return result.append('"').toString();
    }

    private String requireEnv(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }

    private static final class Fingerprint {
        private final String exactHash;
        private final String shapeHash;
        private final String mnemonicHash;
        private final int instructionCount;
        private final int directCallCount;
        private final Set<String> stringAnchors;
        private final long bodySize;

        private Fingerprint(String exactHash, String shapeHash, String mnemonicHash,
                int instructionCount, int directCallCount, Set<String> stringAnchors,
                long bodySize) {
            this.exactHash = exactHash;
            this.shapeHash = shapeHash;
            this.mnemonicHash = mnemonicHash;
            this.instructionCount = instructionCount;
            this.directCallCount = directCallCount;
            this.stringAnchors = stringAnchors;
            this.bodySize = bodySize;
        }
    }
}
