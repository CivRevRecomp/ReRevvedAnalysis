// Ghidra post-script. Dumps a bounded instruction window at selected addresses.
// Environment:
//   REREVVED_TARGET_VAS         comma-separated guest VAs
//   REREVVED_INSTRUCTION_COUNT  optional instructions per target, default 32
//   REREVVED_DUMP_PATH          output path
//@category ReRevved

import java.io.FileWriter;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;

public class DumpInstructions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String targets = requireEnv("REREVVED_TARGET_VAS");
        String outPath = requireEnv("REREVVED_DUMP_PATH");
        int count = parseCount(System.getenv("REREVVED_INSTRUCTION_COUNT"));
        Listing listing = currentProgram.getListing();

        try (PrintWriter out = new PrintWriter(new FileWriter(outPath))) {
            out.println("Program: " + currentProgram.getName());
            out.println("Targets: " + targets);
            out.println("Instruction count: " + count);
            for (String token : targets.split(",")) {
                Address target = toAddr(Long.decode(token.trim()));
                out.printf("%n=== 0x%08X ===%n", target.getOffset());
                InstructionIterator iterator = listing.getInstructions(target, true);
                int emitted = 0;
                while (iterator.hasNext() && emitted < count && !monitor.isCancelled()) {
                    Instruction instruction = iterator.next();
                    out.printf("0x%08X: %s%n",
                        instruction.getAddress().getOffset(), instruction.toString());
                    emitted++;
                }
            }
        }
        println("WROTE: " + outPath);
    }

    private int parseCount(String value) {
        int count = value == null || value.isBlank() ? 32 : Integer.parseInt(value);
        if (count < 1 || count > 256) {
            throw new IllegalArgumentException(
                "REREVVED_INSTRUCTION_COUNT must be 1 through 256");
        }
        return count;
    }

    private String requireEnv(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }
}
