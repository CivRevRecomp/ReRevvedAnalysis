// Ghidra post-script. Dumps defined strings inside one bounded address range.
// Environment:
//   REREVVED_RANGE_START  inclusive guest VA
//   REREVVED_RANGE_END    inclusive guest VA
//   REREVVED_MAX_MATCHES  optional result cap, default 256
//   REREVVED_DUMP_PATH    output path
//@category ReRevved

import java.io.FileWriter;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.util.DefinedDataIterator;

public class DumpStringsInRange extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address start = toAddr(Long.decode(requireEnv("REREVVED_RANGE_START")));
        Address end = toAddr(Long.decode(requireEnv("REREVVED_RANGE_END")));
        String outPath = requireEnv("REREVVED_DUMP_PATH");
        int maxMatches = parseMaxMatches(System.getenv("REREVVED_MAX_MATCHES"));
        if (start.compareTo(end) > 0) {
            throw new IllegalArgumentException(
                "REREVVED_RANGE_START must not exceed REREVVED_RANGE_END");
        }

        int matches = 0;
        try (PrintWriter out = new PrintWriter(new FileWriter(outPath))) {
            out.printf("Program: %s%n", currentProgram.getName());
            out.printf("Range: 0x%08X-0x%08X%n", start.getOffset(), end.getOffset());
            DefinedDataIterator strings = DefinedDataIterator.byDataInstance(
                currentProgram, Data::hasStringValue);
            while (strings.hasNext() && matches < maxMatches &&
                   !monitor.isCancelled()) {
                Data data = strings.next();
                Address address = data.getAddress();
                if (address.compareTo(start) < 0 || address.compareTo(end) > 0) {
                    continue;
                }
                Object value = data.getValue();
                if (!(value instanceof String)) {
                    continue;
                }
                out.printf("0x%08X %s%n", address.getOffset(), escape((String) value));
                matches++;
            }
            out.println("Matches: " + matches);
        }
        println("WROTE: " + outPath);
    }

    private int parseMaxMatches(String value) {
        int maxMatches = value == null || value.isBlank() ? 256 : Integer.parseInt(value);
        if (maxMatches < 1 || maxMatches > 1000) {
            throw new IllegalArgumentException(
                "REREVVED_MAX_MATCHES must be 1 through 1000");
        }
        return maxMatches;
    }

    private String escape(String value) {
        return value.replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n");
    }

    private String requireEnv(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }
}
