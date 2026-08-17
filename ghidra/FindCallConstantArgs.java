// Ghidra post-script. Finds direct calls with a nearby constant argument write.
// Environment:
//   REREVVED_TARGET_VA       direct call target guest VA
//   REREVVED_ARGUMENT_REG    argument register name, for example r5
//   REREVVED_ARGUMENT_VALUE  constant value
//   REREVVED_LOOKBACK        optional instruction limit, default 16
//   REREVVED_DUMP_PATH       output path
//@category ReRevved

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class FindCallConstantArgs extends GhidraScript {
    @Override
    public void run() throws Exception {
        long targetOffset = Long.decode(requireEnv("REREVVED_TARGET_VA"));
        String registerName = requireEnv("REREVVED_ARGUMENT_REG");
        long expected = Long.decode(requireEnv("REREVVED_ARGUMENT_VALUE"));
        int lookback = parseLookback(System.getenv("REREVVED_LOOKBACK"));
        String outPath = requireEnv("REREVVED_DUMP_PATH");
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        Address target = space.getAddress(targetOffset);
        Listing listing = currentProgram.getListing();
        int matches = 0;

        try (PrintWriter out = new PrintWriter(new FileWriter(outPath))) {
            out.println("Program: " + currentProgram.getName());
            out.printf("Target: 0x%08X%n", targetOffset);
            out.println("Argument: " + registerName + " = " + expected);
            ReferenceIterator references = currentProgram.getReferenceManager().getReferencesTo(target);
            while (references.hasNext()) {
                Reference reference = references.next();
                if (!reference.getReferenceType().isCall()) {
                    continue;
                }
                Instruction call = listing.getInstructionAt(reference.getFromAddress());
                Match match = findNearestWrite(listing, call, registerName, expected, lookback);
                if (match == null) {
                    continue;
                }
                out.printf("%n=== call 0x%08X ===%n", call.getAddress().getOffset());
                for (Instruction instruction : match.window) {
                    out.printf("0x%08X: %s%n", instruction.getAddress().getOffset(), instruction);
                }
                matches++;
            }
            out.println("Matches: " + matches);
        }
        println("WROTE: " + outPath);
    }

    private Match findNearestWrite(Listing listing, Instruction call, String registerName,
                                   long expected, int lookback) {
        List<Instruction> reverseWindow = new ArrayList<>();
        Instruction current = listing.getInstructionBefore(call.getAddress());
        for (int index = 0; current != null && index < lookback; index++) {
            reverseWindow.add(current);
            if (writesRegister(current, registerName)) {
                if (!loadsConstant(current, registerName, expected)) {
                    return null;
                }
                Collections.reverse(reverseWindow);
                reverseWindow.add(call);
                return new Match(reverseWindow);
            }
            current = listing.getInstructionBefore(current.getAddress());
        }
        return null;
    }

    private boolean writesRegister(Instruction instruction, String registerName) {
        for (Object object : instruction.getResultObjects()) {
            if (object instanceof Register &&
                ((Register) object).getName().equalsIgnoreCase(registerName)) {
                return true;
            }
        }
        return false;
    }

    private boolean loadsConstant(Instruction instruction, String registerName, long expected) {
        String mnemonic = instruction.getMnemonicString();
        if (!mnemonic.equalsIgnoreCase("li") && !mnemonic.equalsIgnoreCase("lis")) {
            return false;
        }
        Object[] destination = instruction.getOpObjects(0);
        Object[] source = instruction.getOpObjects(1);
        if (destination.length != 1 || !(destination[0] instanceof Register) ||
            !((Register) destination[0]).getName().equalsIgnoreCase(registerName)) {
            return false;
        }
        if (source.length != 1 || !(source[0] instanceof Scalar)) {
            return false;
        }
        return ((Scalar) source[0]).getSignedValue() == expected;
    }

    private int parseLookback(String value) {
        int lookback = value == null || value.isBlank() ? 16 : Integer.parseInt(value);
        if (lookback < 1 || lookback > 64) {
            throw new IllegalArgumentException("REREVVED_LOOKBACK must be 1 through 64");
        }
        return lookback;
    }

    private String requireEnv(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }

    private static final class Match {
        private final List<Instruction> window;

        private Match(List<Instruction> window) {
            this.window = window;
        }
    }
}
