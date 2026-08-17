// Ghidra post-script. Dumps exact function boundaries around selected addresses.
// Environment:
//   REREVVED_TARGET_VAS  exactly one guest VA
//   REREVVED_DUMP_PATH   output path
//   REREVVED_NEIGHBORHOOD_RADIUS  optional bytes per side, default/max 0x40
//   REREVVED_MAX_INSTRUCTIONS    optional instruction cap, default/max 64
//@category ReRevved

import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

public class DumpFunctionNeighborhood extends GhidraScript {
    private enum ReferenceExitState {
        EXHAUSTED,
        CANCELLED,
        LIMIT_REACHED
    }

    private static final int MAX_TARGETS = 1;
    private static final int MAX_REFERENCES_PER_TARGET = 64;
    private static final long MAX_RADIUS = 0x40;
    private static final int MAX_INSTRUCTIONS = 64;
    private static final String REFERENCE_TRUNCATION_MARKER =
        "  [additional references truncated]";

    @Override
    public void run() throws Exception {
        Address target = parseSingleTarget(requireEnv("REREVVED_TARGET_VAS"));
        String normalizedTarget = formatAddress(target);
        String outPath = requireEnv("REREVVED_DUMP_PATH");
        long radius = readBoundedLong("REREVVED_NEIGHBORHOOD_RADIUS",
            MAX_RADIUS, MAX_RADIUS);
        int instructionLimit = (int) readBoundedLong("REREVVED_MAX_INSTRUCTIONS",
            MAX_INSTRUCTIONS, MAX_INSTRUCTIONS);
        FunctionManager functions = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        ReferenceManager references = currentProgram.getReferenceManager();

        try (PrintWriter out = new PrintWriter(new FileWriter(outPath))) {
            out.println("Program: " + currentProgram.getName());
            out.println("Targets: " + normalizedTarget);
            out.printf("Radius: 0x%X bytes per side%n", radius);
            out.println("Maximum instructions per target: " + instructionLimit);
            Function containing = functions.getFunctionContaining(target);
            Function previous = getNeighbor(functions, target, containing, false);
            Function next = getNeighbor(functions, target, containing, true);

            out.printf("%n=== %s ===%n", normalizedTarget);
            dumpFunction(out, "Previous", previous);
            dumpFunction(out, "Containing", containing);
            dumpFunction(out, "Next", next);

            out.println("References to target:");
            ReferenceIterator referenceIterator = references.getReferencesTo(target);
            int referenceCount = 0;
            ReferenceExitState referenceExitState;
            while (true) {
                if (!referenceIterator.hasNext()) {
                    referenceExitState = ReferenceExitState.EXHAUSTED;
                    break;
                }
                if (monitor.isCancelled()) {
                    referenceExitState = ReferenceExitState.CANCELLED;
                    break;
                }
                if (referenceCount >= MAX_REFERENCES_PER_TARGET) {
                    referenceExitState = ReferenceExitState.LIMIT_REACHED;
                    break;
                }
                Reference reference = referenceIterator.next();
                Function owner = functions.getFunctionContaining(reference.getFromAddress());
                out.printf("  %s from %s in %s%n", reference.getReferenceType(),
                    reference.getFromAddress(), owner == null ? "<data>" :
                    owner.getName() + " @ " + owner.getEntryPoint());
                referenceCount++;
            }
            boolean referencesCancelled =
                referenceExitState == ReferenceExitState.CANCELLED;
            boolean referencesTruncated =
                referenceExitState == ReferenceExitState.LIMIT_REACHED;
            if (referencesTruncated) {
                out.println(REFERENCE_TRUNCATION_MARKER);
            }
            out.println("Reference count emitted: " + referenceCount);
            out.println("References cancelled: " + referencesCancelled);
            out.println("References truncated: " + referencesTruncated);

            Address windowStart = subtractClamped(target, radius);
            Address windowEnd = addClamped(target, radius);
            if (containing != null) {
                windowStart = later(windowStart,
                    containing.getBody().getMinAddress());
                windowEnd = earlier(windowEnd,
                    containing.getBody().getMaxAddress());
            }
            else {
                if (previous != null &&
                        previous.getBody().getMaxAddress().compareTo(target) < 0) {
                    windowStart = later(windowStart,
                        previous.getBody().getMinAddress());
                }
                if (next != null &&
                        next.getBody().getMinAddress().compareTo(target) > 0) {
                    windowEnd = earlier(windowEnd,
                        next.getBody().getMaxAddress());
                }
            }
            if (windowStart.compareTo(windowEnd) > 0) {
                throw new IllegalStateException(
                    "Clamped instruction window is empty at " + target);
            }
            out.printf("Instructions 0x%08X..0x%08X:%n",
                windowStart.getOffset(), windowEnd.getOffset());
            InstructionIterator instructions = listing.getInstructions(windowStart, true);
            int instructionCount = 0;
            boolean limitReached = false;
            while (instructions.hasNext() && !monitor.isCancelled()) {
                Instruction instruction = instructions.next();
                if (instruction.getAddress().compareTo(windowEnd) > 0) {
                    break;
                }
                if (instructionCount >= instructionLimit) {
                    limitReached = true;
                    break;
                }
                out.printf("  0x%08X: %s%n", instruction.getAddress().getOffset(),
                    instruction.toString());
                instructionCount++;
            }
            out.println("Instruction count: " + instructionCount);
            if (limitReached) {
                out.println("Instruction limit reached; output is truncated.");
            }
        }
        println("WROTE: " + outPath);
    }

    private Address parseSingleTarget(String rawTargets) {
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        int addressHexDigits = (space.getSize() + 3) / 4;
        int maxLiteralLength = addressHexDigits + 2;
        String normalizedTargets = rawTargets.trim();
        String[] targetLiterals = normalizedTargets.split(",", -1);
        if (targetLiterals.length != MAX_TARGETS) {
            throw new IllegalArgumentException(
                "REREVVED_TARGET_VAS must contain exactly one target");
        }
        String literal = targetLiterals[0].trim();
        if (literal.length() > maxLiteralLength) {
            throw new IllegalArgumentException(
                "REREVVED_TARGET_VAS exceeds the program address width");
        }
        if (literal.isEmpty()) {
            throw new IllegalArgumentException(
                "REREVVED_TARGET_VAS contains an empty target");
        }

        if (!literal.startsWith("0x") && !literal.startsWith("0X")) {
            throw new IllegalArgumentException(
                "REREVVED_TARGET_VAS is not a valid address literal");
        }
        String digits = literal.substring(2);
        if (digits.isEmpty() || digits.length() > addressHexDigits ||
                !digits.matches("[0-9A-Fa-f]+")) {
            throw new IllegalArgumentException(
                "REREVVED_TARGET_VAS is not a valid address literal");
        }

        BigInteger offset = new BigInteger(digits, 16);
        if (offset.bitLength() > space.getSize()) {
            throw new IllegalArgumentException(
                "REREVVED_TARGET_VAS exceeds the program address width");
        }
        Address target = space.getAddress(offset.longValue());
        if (!currentProgram.getMemory().contains(target)) {
            throw new IllegalArgumentException(
                "Target is outside program memory: " + formatAddress(target));
        }
        return target;
    }

    private String formatAddress(Address address) {
        int addressHexDigits = (address.getAddressSpace().getSize() + 3) / 4;
        return String.format("0x%0" + addressHexDigits + "X", address.getOffset());
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

    private Function getNeighbor(FunctionManager functions, Address target,
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

    private Address subtractClamped(Address address, long amount) {
        Address minimum = address.getAddressSpace().getMinAddress();
        return address.subtract(minimum) < amount ? minimum : address.subtract(amount);
    }

    private Address addClamped(Address address, long amount) {
        Address maximum = address.getAddressSpace().getMaxAddress();
        return maximum.subtract(address) < amount ? maximum : address.add(amount);
    }

    private Address later(Address first, Address second) {
        return first.compareTo(second) >= 0 ? first : second;
    }

    private Address earlier(Address first, Address second) {
        return first.compareTo(second) <= 0 ? first : second;
    }

    private long readBoundedLong(String name, long defaultValue, long maximum) {
        String raw = System.getenv(name);
        if (raw == null) {
            return defaultValue;
        }
        if (raw.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        final long value;
        try {
            value = Long.decode(raw.trim());
        }
        catch (NumberFormatException exception) {
            throw new IllegalArgumentException(name + " is not a valid integer", exception);
        }
        if (value <= 0 || value > maximum) {
            throw new IllegalArgumentException(String.format(
                "%s must be between 1 and 0x%X", name, maximum));
        }
        return value;
    }

    private String requireEnv(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }
}
