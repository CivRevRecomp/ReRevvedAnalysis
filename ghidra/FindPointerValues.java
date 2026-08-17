// Ghidra post-script. Finds exact aligned 32-bit pointer values in memory.
// Environment:
//   REREVVED_POINTER_VAS  comma-separated guest VAs
//   REREVVED_MAX_MATCHES  optional matches per value, default 100
//   REREVVED_DUMP_PATH    output path
//@category ReRevved

import java.io.FileWriter;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class FindPointerValues extends GhidraScript {
    @Override
    public void run() throws Exception {
        String targets = requireEnv("REREVVED_POINTER_VAS");
        String outPath = requireEnv("REREVVED_DUMP_PATH");
        int maxMatches = parseMaxMatches(System.getenv("REREVVED_MAX_MATCHES"));
        Memory memory = currentProgram.getMemory();

        try (PrintWriter out = new PrintWriter(new FileWriter(outPath))) {
            out.println("Program: " + currentProgram.getName());
            out.println("Pointer VAs: " + targets);
            for (String token : targets.split(",")) {
                long value = Long.decode(token.trim());
                int matches = 0;
                out.printf("%n=== 0x%08X ===%n", value);
                for (MemoryBlock block : memory.getBlocks()) {
                    if (!block.isInitialized() || monitor.isCancelled()) {
                        continue;
                    }
                    Address current = align(block.getStart());
                    Address end = block.getEnd();
                    while (current.compareTo(end) <= 0 && matches < maxMatches &&
                           !monitor.isCancelled()) {
                        if (current.add(3).compareTo(end) > 0) {
                            break;
                        }
                        int word = memory.getInt(current);
                        if (Integer.toUnsignedLong(word) == value) {
                            out.printf("0x%08X%n", current.getOffset());
                            matches++;
                        }
                        current = current.add(4);
                    }
                    if (matches >= maxMatches) {
                        break;
                    }
                }
                out.println("Matches: " + matches);
            }
        }
        println("WROTE: " + outPath);
    }

    private Address align(Address address) {
        long offset = address.getOffset();
        return address.add((4 - (offset & 3)) & 3);
    }

    private int parseMaxMatches(String value) {
        int maxMatches = value == null || value.isBlank() ? 100 : Integer.parseInt(value);
        if (maxMatches < 1 || maxMatches > 1000) {
            throw new IllegalArgumentException("REREVVED_MAX_MATCHES must be 1 through 1000");
        }
        return maxMatches;
    }

    private String requireEnv(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }
}
