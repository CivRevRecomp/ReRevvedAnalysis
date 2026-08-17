// Ghidra post-script. Dumps exact string references and a bounded native closure.
// Environment:
//   REREVVED_EXACT_STRINGS  comma-separated exact defined strings
//   REREVVED_TARGET_VAS     optional comma-separated guest function VAs
//   REREVVED_MAX_FUNCTIONS  optional closure cap, default 48
//   REREVVED_DUMP_PATH      output path
//@category ReRevved

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.util.DefinedDataIterator;

public class DumpStringBoundary extends GhidraScript {
    @Override
    public void run() throws Exception {
        List<String> exactStrings = parseList(requireEnv("REREVVED_EXACT_STRINGS"));
        List<String> targetVas = parseList(System.getenv("REREVVED_TARGET_VAS"));
        int maxFunctions = parseLimit(System.getenv("REREVVED_MAX_FUNCTIONS"));
        String outPath = requireEnv("REREVVED_DUMP_PATH");
        FunctionManager functions = currentProgram.getFunctionManager();
        ReferenceManager references = currentProgram.getReferenceManager();
        Memory memory = currentProgram.getMemory();
        Map<Address, Function> roots = new LinkedHashMap<>();
        List<String> referenceLines = new ArrayList<>();

        DefinedDataIterator strings = DefinedDataIterator.byDataInstance(
            currentProgram, Data::hasStringValue);
        while (strings.hasNext() && !monitor.isCancelled()) {
            Data data = strings.next();
            Object value = data.getValue();
            if (!(value instanceof String) || !exactStrings.contains((String) value)) {
                continue;
            }
            long count = 0;
            List<String> stringLines = new ArrayList<>();
            ReferenceIterator iterator = references.getReferencesTo(data.getAddress());
            while (iterator.hasNext()) {
                Reference reference = iterator.next();
                Address source = reference.getFromAddress();
                Function owner = functions.getFunctionContaining(source);
                if (owner != null) {
                    roots.put(owner.getEntryPoint(), owner);
                } else {
                    followRegistrationWindow(source, references, functions, memory, roots, stringLines);
                }
                stringLines.add(String.format(
                    "  %s from %s in %s",
                    reference.getReferenceType(), source,
                    owner == null ? "<data>" : owner.getName() + " @ " + owner.getEntryPoint()));
                count++;
            }
            referenceLines.add(String.format(
                "String 0x%08X refs=%d %s",
                data.getAddress().getOffset(), count, escape((String) value)));
            referenceLines.addAll(stringLines);
        }

        for (String token : targetVas) {
            Address address = toAddr(Long.decode(token));
            Function function = functions.getFunctionAt(address);
            if (function == null) {
                function = functions.getFunctionContaining(address);
            }
            if (function != null) {
                roots.put(function.getEntryPoint(), function);
            } else {
                referenceLines.add("Seed has no containing function: " + token);
            }
        }

        Map<Address, Function> closure = new LinkedHashMap<>(roots);
        for (Function root : new ArrayList<>(roots.values())) {
            addFunctions(closure, root.getCallingFunctions(monitor), maxFunctions);
            addFunctions(closure, root.getCalledFunctions(monitor), maxFunctions);
        }
        if (closure.size() > maxFunctions) {
            throw new IllegalStateException(
                "bounded closure exceeds REREVVED_MAX_FUNCTIONS=" + maxFunctions);
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try (BufferedWriter out = new BufferedWriter(new FileWriter(new File(outPath)))) {
            out.write("Program: " + currentProgram.getName());
            out.newLine();
            out.write("Exact strings: " + String.join(",", exactStrings));
            out.newLine();
            out.write("Seed VAs: " + String.join(",", targetVas));
            out.newLine();
            out.write("Root functions: " + roots.size());
            out.newLine();
            out.write("Closure functions: " + closure.size());
            out.newLine();
            out.newLine();
            out.write("=== STRING REFERENCES ===");
            out.newLine();
            for (String line : referenceLines) {
                out.write(line);
                out.newLine();
            }

            for (Function function : closure.values()) {
                out.newLine();
                out.write(String.format("=== FUNCTION 0x%08X ===", function.getEntryPoint().getOffset()));
                out.newLine();
                out.write("Name: " + function.getName());
                out.newLine();
                out.write("Signature: " + function.getSignature());
                out.newLine();
                out.write("Role: " + (roots.containsKey(function.getEntryPoint()) ? "root" : "direct-neighbor"));
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
                out.write("Decompilation:");
                out.newLine();
                DecompileResults result = decompiler.decompileFunction(function, 180, monitor);
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

    private void addFunctions(
        Map<Address, Function> destination,
        Collection<Function> additions,
        int maxFunctions
    ) {
        for (Function function : additions) {
            destination.put(function.getEntryPoint(), function);
            if (destination.size() > maxFunctions) {
                return;
            }
        }
    }

    private void followRegistrationWindow(
        Address center,
        ReferenceManager references,
        FunctionManager functions,
        Memory memory,
        Map<Address, Function> roots,
        List<String> lines
    ) {
        lines.add(String.format("  Registration window centered at 0x%08X:", center.getOffset()));
        for (long delta = -0x20; delta <= 0x20; delta += 4) {
            Address address = center.add(delta);
            try {
                int value = memory.getInt(address);
                lines.add(String.format("    0x%08X = 0x%08X", address.getOffset(), value));
            } catch (MemoryAccessException exception) {
                lines.add(String.format("    0x%08X = <unreadable>", address.getOffset()));
            }
            ReferenceIterator users = references.getReferencesTo(address);
            while (users.hasNext()) {
                Reference user = users.next();
                Function owner = functions.getFunctionContaining(user.getFromAddress());
                lines.add(String.format(
                    "      %s from %s in %s",
                    user.getReferenceType(), user.getFromAddress(),
                    owner == null ? "<data>" : owner.getName() + " @ " + owner.getEntryPoint()));
                if (owner != null) {
                    roots.put(owner.getEntryPoint(), owner);
                }
            }
        }
    }

    private List<String> parseList(String value) {
        List<String> values = new ArrayList<>();
        if (value == null || value.isBlank()) {
            return values;
        }
        for (String token : value.split(",")) {
            String trimmed = token.trim();
            if (!trimmed.isEmpty()) {
                values.add(trimmed);
            }
        }
        return values;
    }

    private int parseLimit(String value) {
        int limit = value == null || value.isBlank() ? 48 : Integer.parseInt(value);
        if (limit < 1 || limit > 96) {
            throw new IllegalArgumentException("REREVVED_MAX_FUNCTIONS must be 1 through 96");
        }
        return limit;
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
