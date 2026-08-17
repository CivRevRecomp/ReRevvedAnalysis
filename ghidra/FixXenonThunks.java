// Ghidra mutating post-script. Repairs undecodable Xenon VMX128 thunk slots.
// Run first through tools/bootstrap-ghidra.ps1 against a disposable project.
//@category ReRevved
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.framework.options.Options;
import ghidra.framework.options.OptionType;

public class FixXenonThunks extends GhidraScript {
    private static final byte[] BLR = { 0x4E, (byte) 0x80, 0x00, 0x20 }; // PPC big-endian `blr`

    @Override
    public void run() throws Exception {
        requireBootstrapGuard();

        // Disable Non-Returning Functions analyzers before patching; otherwise
        // auto-analysis can restore the noreturn flags on these thunks.
        disableNoReturnAnalyzers();

        String[] a = getScriptArgs();
        long lo = a.length >= 1 ? parseHex(a[0]) : 0x827F3F50L;
        long hi = a.length >= 2 ? parseHex(a[1]) : 0x827F4280L;

        int patched = 0, cleared = 0, seen = 0;
        // Visit each four-byte thunk slot. Repair undecodable entries and clear
        // stale noreturn flags from entries that already decode as `blr`.
        for (long va = lo; va < hi; va += 4) {
            Address addr = toAddr(va);
            seen++;
            if (getInstructionAt(addr) == null) {          // (1) undecodable VMX128 slot
                clearListing(addr, addr.add(3));
                setBytes(addr, BLR);
                disassemble(addr);
                patched++;
            }
            Function fn = getFunctionAt(addr);
            if (fn == null) fn = createFunction(addr, "vmx128_thunk_" + Long.toHexString(va));
            if (fn != null && fn.hasNoReturn()) { fn.setNoReturn(false); cleared++; } // (2)
        }
        println("[fixthunks] " + seen + " thunk slots in [" + Long.toHexString(lo) + ","
            + Long.toHexString(hi) + "): patched " + patched + " bad-data to blr, cleared noreturn on "
            + cleared + ". Next: RebuildTruncatedFunctions, then RecoverSplitConstRefs.");
    }

    // Disable every boolean analyzer toggle whose name mentions "Non-Returning" (Discovered + Known).
    // Iterating by substring is robust to the exact option key; numeric sub-options are skipped by
    // the BOOLEAN_TYPE guard. Options live under the "Analyzers" program-options category.
    private void disableNoReturnAnalyzers() {
        Options analyzers = currentProgram.getOptions("Analyzers");
        int off = 0;
        for (String opt : analyzers.getOptionNames()) {
            if (opt.contains("Non-Returning") && analyzers.getType(opt) == OptionType.BOOLEAN_TYPE) {
                analyzers.setBoolean(opt, false);
                off++;
            }
        }
        println("[fixthunks] disabled " + off + " Non-Returning analyzer toggle(s).");
    }

    private void requireBootstrapGuard() {
        String guard = System.getenv("REREVVED_GHIDRA_MUTATION");
        if (!"ALLOW_DISPOSABLE_PROJECT".equals(guard)) {
            throw new IllegalStateException(
                "Repair scripts require tools/bootstrap-ghidra.ps1 and a disposable project.");
        }
    }

    private static long parseHex(String s) {
        s = s.trim();
        if (s.toLowerCase().startsWith("0x")) s = s.substring(2);
        return Long.parseLong(s, 16);
    }
}
