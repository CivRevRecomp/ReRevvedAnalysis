// Ghidra post-script. Prints defined data values at selected guest VAs.
// Environment:
//   REREVVED_TARGET_VAS  comma-separated guest VAs
//   REREVVED_DUMP_PATH   output path
//@category ReRevved

import java.io.FileWriter;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;

public class DumpDataValues extends GhidraScript {
    @Override
    public void run() throws Exception {
        String targets = requireEnv("REREVVED_TARGET_VAS");
        String outPath = requireEnv("REREVVED_DUMP_PATH");
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        Listing listing = currentProgram.getListing();

        try (PrintWriter out = new PrintWriter(new FileWriter(outPath))) {
            out.println("Program: " + currentProgram.getName());
            out.println("VAs: " + targets);
            for (String token : targets.split(",")) {
                long offset = Long.decode(token.trim());
                Address address = space.getAddress(offset);
                Data data = listing.getDefinedDataAt(address);
                out.printf("%n=== 0x%08X ===%n", offset);
                if (data == null) {
                    out.println("No defined data at address");
                    continue;
                }
                out.println("Type: " + data.getDataType().getDisplayName());
                out.println("Length: " + data.getLength());
                out.println("Value: " + escape(String.valueOf(data.getValue())));
                out.println("Representation: " + escape(data.getDefaultValueRepresentation()));
            }
        }
        println("WROTE: " + outPath);
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
