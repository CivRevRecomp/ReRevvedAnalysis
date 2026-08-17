// Ghidra post-script. Dumps bounded big-endian words around selected addresses.
// Environment:
//   REREVVED_TARGET_VAS  comma-separated guest VAs
//   REREVVED_WORD_RADIUS optional word count before and after, default 8
//   REREVVED_DUMP_PATH   output path
//@category ReRevved

import java.io.FileWriter;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;

public class DumpMemoryWords extends GhidraScript {
    @Override
    public void run() throws Exception {
        String targets = requireEnv("REREVVED_TARGET_VAS");
        String outPath = requireEnv("REREVVED_DUMP_PATH");
        int radius = parseRadius(System.getenv("REREVVED_WORD_RADIUS"));

        try (PrintWriter out = new PrintWriter(new FileWriter(outPath))) {
            out.println("Program: " + currentProgram.getName());
            out.println("Targets: " + targets);
            out.println("Word radius: " + radius);
            for (String token : targets.split(",")) {
                Address target = toAddr(Long.decode(token.trim()));
                out.printf("%n=== 0x%08X ===%n", target.getOffset());
                for (int index = -radius; index <= radius; index++) {
                    Address address = target.add((long) index * 4);
                    int value = getInt(address);
                    Address pointer = toAddr(Integer.toUnsignedLong(value));
                    Symbol symbol = getSymbolAt(pointer);
                    out.printf("%s0x%08X: 0x%08X%s%n",
                        index == 0 ? "> " : "  ", address.getOffset(), value,
                        symbol == null ? "" : " " + symbol.getName());
                }
            }
        }
        println("WROTE: " + outPath);
    }

    private int parseRadius(String value) {
        int radius = value == null || value.isBlank() ? 8 : Integer.parseInt(value);
        if (radius < 0 || radius > 64) {
            throw new IllegalArgumentException("REREVVED_WORD_RADIUS must be 0 through 64");
        }
        return radius;
    }

    private String requireEnv(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }
}
