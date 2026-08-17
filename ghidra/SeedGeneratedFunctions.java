// Ghidra mutating post-script. Seeds code from the ReXGlue function map.
// Run after structural repairs through tools/bootstrap-ghidra.ps1.
//@category ReRevved
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SeedGeneratedFunctions extends GhidraScript {
    private static final Pattern MAPPING = Pattern.compile(
        "\\{\\s*0x([0-9A-Fa-f]{8})\\s*,\\s*sub_[0-9A-Fa-f]{8}\\s*\\},");

    @Override
    public void run() throws Exception {
        requireBootstrapGuard();

        String mapPath = System.getenv("REREVVED_FUNCTION_MAP");
        if (mapPath == null || mapPath.trim().isEmpty()) {
            throw new IllegalStateException("REREVVED_FUNCTION_MAP is required.");
        }

        Path path = Paths.get(mapPath);
        List<Address> entries = new ArrayList<>();
        AddressSet seeds = new AddressSet();
        for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
            Matcher match = MAPPING.matcher(line);
            if (!match.find()) continue;
            Address entry = toAddr(Long.parseUnsignedLong(match.group(1), 16));
            entries.add(entry);
            seeds.add(entry);
        }
        if (entries.isEmpty()) {
            throw new IllegalStateException("No ReXGlue function mappings found in " + path);
        }
        int explicitSeeds = addExplicitSeeds(seeds);

        DisassembleCommand command = new DisassembleCommand(seeds, null, true);
        if (!command.applyTo(currentProgram, monitor)) {
            throw new IllegalStateException("Batch disassembly failed: " + command.getStatusMsg());
        }

        int created = 0, existing = 0, contained = 0, undecoded = 0;
        List<Address> undecodedSamples = new ArrayList<>();
        for (Address entry : entries) {
            monitor.checkCancelled();
            if (getInstructionAt(entry) == null) {
                undecoded++;
                if (undecodedSamples.size() < 16) undecodedSamples.add(entry);
                continue;
            }
            Function function = getFunctionAt(entry);
            if (function != null) {
                existing++;
                continue;
            }
            function = getFunctionContaining(entry);
            if (function != null) {
                contained++;
                continue;
            }
            if (createFunction(entry, null) != null) created++;
        }

        println("[seed] parsed " + entries.size() + " mappings; created " + created
            + " functions, kept " + existing + " entries, skipped " + contained
            + " contained entries, undecoded " + undecoded + "; added "
            + explicitSeeds + " explicit code seeds.");
        if (!undecodedSamples.isEmpty()) {
            println("[seed] first undecoded entries: " + undecodedSamples);
        }
        if (undecoded * 20 > entries.size()) {
            throw new IllegalStateException(
                "ReXGlue function-map seeding decoded fewer than 95 percent of entries.");
        }
    }

    private int addExplicitSeeds(AddressSet seeds) {
        String raw = System.getenv("REREVVED_CODE_SEED_SITES");
        if (raw == null || raw.trim().isEmpty()) return 0;
        int count = 0;
        for (String token : raw.split(",")) {
            String value = token.trim();
            if (value.isEmpty()) continue;
            if (value.toLowerCase().startsWith("0x")) value = value.substring(2);
            seeds.add(toAddr(Long.parseUnsignedLong(value, 16)));
            count++;
        }
        return count;
    }

    private void requireBootstrapGuard() {
        String guard = System.getenv("REREVVED_GHIDRA_MUTATION");
        if (!"ALLOW_DISPOSABLE_PROJECT".equals(guard)) {
            throw new IllegalStateException(
                "Repair scripts require tools/bootstrap-ghidra.ps1 and a disposable project.");
        }
    }
}
