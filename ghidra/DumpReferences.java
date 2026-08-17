// Ghidra post-script. Dumps references to selected guest addresses.
// Environment:
//   REREVVED_TARGET_VAS  comma-separated guest VAs
//   REREVVED_DUMP_PATH   output path
//@category ReRevved

import java.io.FileWriter;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

public class DumpReferences extends GhidraScript {
    @Override
    public void run() throws Exception {
        String targets = requireEnv("REREVVED_TARGET_VAS");
        String outPath = requireEnv("REREVVED_DUMP_PATH");
        FunctionManager functions = currentProgram.getFunctionManager();
        ReferenceManager references = currentProgram.getReferenceManager();

        try (PrintWriter out = new PrintWriter(new FileWriter(outPath))) {
            out.println("Program: " + currentProgram.getName());
            out.println("Targets: " + targets);
            for (String token : targets.split(",")) {
                Address target = toAddr(Long.decode(token.trim()));
                long count = 0;
                out.printf("%n=== 0x%08X ===%n", target.getOffset());
                ReferenceIterator iterator = references.getReferencesTo(target);
                while (iterator.hasNext() && !monitor.isCancelled()) {
                    Reference reference = iterator.next();
                    Address source = reference.getFromAddress();
                    Function function = functions.getFunctionContaining(source);
                    String owner = function == null
                        ? "<data>"
                        : function.getName() + " @ " + function.getEntryPoint();
                    out.printf("  %s from %s in %s%n",
                        reference.getReferenceType(), source, owner);
                    count++;
                }
                out.println("References: " + count);
            }
        }
        println("WROTE: " + outPath);
    }

    private String requireEnv(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }
}
