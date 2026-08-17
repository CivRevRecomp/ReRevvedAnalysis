// Ghidra post-script. Dumps selected functions, callers, and callees.
// Environment:
//   REREVVED_TARGET_VAS  comma-separated guest VAs
//   REREVVED_DUMP_PATH   output path
//@category ReRevved

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class DumpFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String vas = System.getenv("REREVVED_TARGET_VAS");
        String outPath = System.getenv("REREVVED_DUMP_PATH");
        if (vas == null || vas.isBlank()) {
            throw new IllegalArgumentException("REREVVED_TARGET_VAS is required");
        }
        if (outPath == null || outPath.isBlank()) {
            throw new IllegalArgumentException("REREVVED_DUMP_PATH is required");
        }

        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        FunctionManager functions = currentProgram.getFunctionManager();
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        try (BufferedWriter out = new BufferedWriter(new FileWriter(new File(outPath)))) {
            out.write("Program: " + currentProgram.getName());
            out.newLine();
            out.write("VAs: " + vas);
            out.newLine();

            for (String token : vas.split(",")) {
                long value = Long.decode(token.trim());
                Address address = space.getAddress(value);
                Function function = functions.getFunctionAt(address);
                if (function == null) function = functions.getFunctionContaining(address);

                out.newLine();
                out.write(String.format("=== 0x%08X ===", value));
                out.newLine();
                if (function == null) {
                    out.write("No containing function");
                    out.newLine();
                    continue;
                }

                out.write("Name: " + function.getName());
                out.newLine();
                out.write("Entry: " + function.getEntryPoint());
                out.newLine();
                out.write("Signature: " + function.getSignature());
                out.newLine();
                out.write("Callers:");
                out.newLine();
                for (Function caller : function.getCallingFunctions(monitor)) {
                    out.write("  " + caller.getName() + " @ " + caller.getEntryPoint());
                    out.newLine();
                }
                out.write("Callees:");
                out.newLine();
                for (Function callee : function.getCalledFunctions(monitor)) {
                    out.write("  " + callee.getName() + " @ " + callee.getEntryPoint());
                    out.newLine();
                }

                DecompileResults result = decompiler.decompileFunction(function, 180, monitor);
                out.write("Decompilation:");
                out.newLine();
                if (result.decompileCompleted()) {
                    out.write(result.getDecompiledFunction().getC());
                } else {
                    out.write("FAILED: " + result.getErrorMessage());
                }
                out.newLine();
            }
        } finally {
            decompiler.dispose();
        }
        println("WROTE: " + outPath);
    }
}
