// Ghidra mutating post-script. Recovers split PowerPC constant references.
// Run last through tools/bootstrap-ghidra.ps1 against a disposable project.
//@category ReRevved
import ghidra.app.plugin.core.analysis.PowerPCAddressAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

public class RecoverSplitConstRefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        requireBootstrapGuard();

        ReferenceManager rm = currentProgram.getReferenceManager();
        long before = countMemRefs(rm);
        println("[constref] memory references before: " + before);

        PowerPCAddressAnalyzer analyzer = new PowerPCAddressAnalyzer();
        // Load the analyzer's current option values before running it.
        Options options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        analyzer.registerOptions(options, currentProgram);
        analyzer.optionsChanged(options, currentProgram);

        MessageLog log = new MessageLog();
        // Run the analyzer over initialized memory without enabling other analyzers.
        analyzer.added(currentProgram, currentProgram.getMemory(), monitor, log);

        long after = countMemRefs(rm);
        println("[constref] memory references after: " + after + " (added " + (after - before) + ").");
        String lg = log.toString();
        if (lg != null && lg.trim().length() > 0) println("[constref] analyzer log: " + lg.trim());

        // Verify the analyzer's result at representative acceptance-gate sites.
        long[] froms = envAddresses(
            "REREVVED_CONSTREF_ACCEPT_SITES",
            new long[] { 0x82dab144L, 0x82dab14cL, 0x82dab154L });
        for (long v : froms) {
            Reference[] rs = rm.getReferencesFrom(toAddr(v));
            StringBuilder sb = new StringBuilder();
            for (Reference r : rs) sb.append(r.getToAddress()).append("[").append(r.getReferenceType()).append("] ");
            println("  [from] " + Long.toHexString(v) + " -> " + rs.length + " : " + sb);
        }

        // Acceptance self-check.
        long target = envAddress("REREVVED_CONSTREF_ACCEPT_TARGET", 0x821b15c0L);
        String targetText = String.format("%08x", target);
        Address t = toAddr(target);
        ReferenceIterator ri = rm.getReferencesTo(t);
        int c = 0;
        while (ri.hasNext()) {
            Reference r = ri.next();
            println("  [check] " + targetText + " <- " + r.getFromAddress() +
                " (" + r.getReferenceType() + ")");
            c++;
        }
        println("[constref] references to " + targetText + " now: " + c +
            " (expected >= 1).");
        if (c < 1) {
            throw new IllegalStateException(
                "Split-constant recovery did not restore the acceptance reference.");
        }
    }

    private long envAddress(String name, long fallback) {
        String value = System.getenv(name);
        if (value == null || value.trim().isEmpty()) return fallback;
        return Long.decode(value.trim());
    }

    private long[] envAddresses(String name, long[] fallback) {
        String value = System.getenv(name);
        if (value == null || value.trim().isEmpty()) return fallback;
        String[] parts = value.split(",");
        long[] result = new long[parts.length];
        for (int i = 0; i < parts.length; i++) result[i] = Long.decode(parts[i].trim());
        return result;
    }

    private long countMemRefs(ReferenceManager rm) {
        long n = 0;
        ghidra.program.model.address.AddressIterator it =
            rm.getReferenceSourceIterator(currentProgram.getMemory(), true);
        while (it.hasNext()) { n += rm.getReferenceCountFrom(it.next()); }
        return n;
    }

    private void requireBootstrapGuard() {
        String guard = System.getenv("REREVVED_GHIDRA_MUTATION");
        if (!"ALLOW_DISPOSABLE_PROJECT".equals(guard)) {
            throw new IllegalStateException(
                "Repair scripts require tools/bootstrap-ghidra.ps1 and a disposable project.");
        }
    }
}
