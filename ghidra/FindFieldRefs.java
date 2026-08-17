// Ghidra post-script. Finds PowerPC register-plus-displacement operands.
// Environment:
//   REREVVED_FIELD_OFFSETS  comma-separated hex offsets
//   REREVVED_FUNCTION_VAS   optional comma-separated containing-function VAs
//   REREVVED_BASE_REGS      optional comma-separated register names
//   REREVVED_DUMP_PATH      output path
//@category ReRevved

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.HashSet;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.scalar.Scalar;

public class FindFieldRefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        Set<Long> offsets = parseHexSet(requireEnv("REREVVED_FIELD_OFFSETS"));
        Set<Long> functionEntries = parseHexSet(System.getenv("REREVVED_FUNCTION_VAS"));
        Set<String> baseRegisters = parseRegisterSet(System.getenv("REREVVED_BASE_REGS"));
        String outPath = requireEnv("REREVVED_DUMP_PATH");

        FunctionManager functions = currentProgram.getFunctionManager();
        long scanned = 0;
        long hits = 0;

        try (PrintWriter out = new PrintWriter(new FileWriter(outPath))) {
            out.println("Offsets: " + System.getenv("REREVVED_FIELD_OFFSETS"));
            out.println("Functions: " + System.getenv("REREVVED_FUNCTION_VAS"));

            InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
            while (instructions.hasNext() && !monitor.isCancelled()) {
                Instruction instruction = instructions.next();
                Function function = functions.getFunctionContaining(instruction.getAddress());
                if (function == null) continue;
                long entry = function.getEntryPoint().getOffset();
                if (!functionEntries.isEmpty() && !functionEntries.contains(entry)) continue;
                scanned++;

                for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
                    Long displacement = null;
                    String base = null;
                    for (Object object : instruction.getOpObjects(operand)) {
                        if (object instanceof Scalar) {
                            long value = ((Scalar) object).getUnsignedValue();
                            if (offsets.contains(value)) displacement = value;
                        } else if (object instanceof Register && base == null) {
                            base = ((Register) object).getName().toUpperCase();
                        }
                    }
                    if (displacement == null || base == null) continue;
                    if (baseRegisters.isEmpty()) {
                        if (base.equals("R1")) continue;
                    } else if (!baseRegisters.contains(base)) {
                        continue;
                    }

                    hits++;
                    out.printf("0x%08X\t%s\t0x%08X\top%d\t%s\t+0x%X\t%s%n",
                        entry, function.getName(), instruction.getAddress().getOffset(), operand,
                        base, displacement, instruction.toString());
                }
            }
            out.printf("Scanned %d instructions; found %d hits.%n", scanned, hits);
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

    private Set<Long> parseHexSet(String value) {
        Set<Long> result = new HashSet<>();
        if (value == null || value.isBlank()) return result;
        for (String token : value.split(",")) result.add(Long.decode(token.trim()));
        return result;
    }

    private Set<String> parseRegisterSet(String value) {
        Set<String> result = new HashSet<>();
        if (value == null || value.isBlank()) return result;
        for (String token : value.split(",")) result.add(token.trim().toUpperCase());
        return result;
    }
}
