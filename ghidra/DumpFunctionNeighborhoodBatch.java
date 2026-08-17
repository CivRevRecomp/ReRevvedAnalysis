// Ghidra post-script for one bounded multi-target neighborhood dump.
// Environment:
//   REREVVED_TARGET_VAS  comma-separated guest VAs, maximum 32
//   REREVVED_DUMP_PATH   output path
//@category ReRevved

import java.io.FileWriter;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;

public class DumpFunctionNeighborhoodBatch extends GhidraScript {
    private static final int MAX_TARGETS = 32;
    private static final int WORD_RADIUS = 4;
    private static final long INSTRUCTION_BEFORE = 0x20;
    private static final long INSTRUCTION_AFTER = 0x40;
    private static final int MAX_INSTRUCTIONS = 32;
    private static final int MAX_REFERENCES = 64;

    @Override
    public void run() throws Exception {
        String rawTargets = requireEnv("REREVVED_TARGET_VAS");
        String outPath = requireEnv("REREVVED_DUMP_PATH");
        String[] tokens = rawTargets.split(",", -1);
        if (tokens.length < 1 || tokens.length > MAX_TARGETS) {
            throw new IllegalArgumentException("REREVVED_TARGET_VAS must contain 1 through 32 targets");
        }

        FunctionManager functions = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        ReferenceManager references = currentProgram.getReferenceManager();

        try (PrintWriter out = new PrintWriter(new FileWriter(outPath))) {
            out.println("Program: " + currentProgram.getName());
            out.println("Targets: " + rawTargets);
            out.println("Target cap: " + MAX_TARGETS);
            out.printf("Words: +/-0x%X; instructions: -0x%X..+0x%X; reference cap: %d%n",
                WORD_RADIUS * 4, INSTRUCTION_BEFORE, INSTRUCTION_AFTER, MAX_REFERENCES);

            for (String token : tokens) {
                Address target = toAddr(Long.decode(token.trim()));
                out.printf("%n=== 0x%08X ===%n", target.getOffset());

                Function containing = functions.getFunctionContaining(target);
                dumpFunction(out, "Previous", neighbor(functions, target, containing, false));
                dumpFunction(out, "Containing", containing);
                dumpFunction(out, "Next", neighbor(functions, target, containing, true));

                out.println("References to target:");
                ReferenceIterator referenceIterator = references.getReferencesTo(target);
                int referenceCount = 0;
                while (referenceIterator.hasNext()) {
                    if (referenceCount >= MAX_REFERENCES || monitor.isCancelled()) {
                        break;
                    }
                    Reference reference = referenceIterator.next();
                    Function owner = functions.getFunctionContaining(reference.getFromAddress());
                    out.printf("  %s from %s in %s%n", reference.getReferenceType(),
                        reference.getFromAddress(), owner == null ? "<data>" :
                        owner.getName() + " @ " + owner.getEntryPoint());
                    referenceCount++;
                }
                out.println("Reference count emitted: " + referenceCount);
                out.println("References truncated: " + referenceIterator.hasNext());

                out.println("Words:");
                for (int index = -WORD_RADIUS; index <= WORD_RADIUS; index++) {
                    Address address = target.add((long) index * 4);
                    int value = getInt(address);
                    Symbol pointerSymbol = getSymbolAt(toAddr(Integer.toUnsignedLong(value)));
                    Instruction exact = listing.getInstructionAt(address);
                    out.printf("  0x%08X: 0x%08X%s%s%n", address.getOffset(), value,
                        exact == null ? "" : " instruction=" + exact,
                        pointerSymbol == null ? "" : " pointerSymbol=" + pointerSymbol.getName());
                }

                Address start = target.subtract(INSTRUCTION_BEFORE);
                Address end = target.add(INSTRUCTION_AFTER);
                out.printf("Decoded instructions 0x%08X..0x%08X:%n", start.getOffset(), end.getOffset());
                InstructionIterator iterator = listing.getInstructions(start, true);
                int emitted = 0;
                while (iterator.hasNext() && emitted < MAX_INSTRUCTIONS && !monitor.isCancelled()) {
                    Instruction instruction = iterator.next();
                    if (instruction.getAddress().compareTo(end) > 0) {
                        break;
                    }
                    out.printf("  0x%08X: %s%n", instruction.getAddress().getOffset(), instruction);
                    emitted++;
                }
                out.println("Instruction count emitted: " + emitted);
            }
        }
        println("WROTE: " + outPath);
    }

    private Function neighbor(FunctionManager functions, Address target,
            Function containing, boolean forward) {
        FunctionIterator iterator = functions.getFunctions(target, forward);
        while (iterator.hasNext()) {
            Function candidate = iterator.next();
            if (candidate != containing) {
                return candidate;
            }
        }
        return null;
    }

    private void dumpFunction(PrintWriter out, String label, Function function) {
        if (function == null) {
            out.println(label + ": <none>");
            return;
        }
        out.printf("%s: %s entry=%s min=%s max=%s bodyBytes=0x%X%n", label,
            function.getName(), function.getEntryPoint(), function.getBody().getMinAddress(),
            function.getBody().getMaxAddress(), function.getBody().getNumAddresses());
    }

    private String requireEnv(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }
}
