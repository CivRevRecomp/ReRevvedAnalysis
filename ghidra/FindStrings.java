// Ghidra post-script. Finds defined strings containing selected text.
// Environment:
//   REREVVED_STRING_TERMS  comma-separated case-insensitive substrings
//   REREVVED_MAX_MATCHES   optional result cap, default 200
//   REREVVED_DUMP_PATH     output path
//@category ReRevved

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.util.DefinedDataIterator;

public class FindStrings extends GhidraScript {
    @Override
    public void run() throws Exception {
        List<String> terms = parseTerms(requireEnv("REREVVED_STRING_TERMS"));
        String outPath = requireEnv("REREVVED_DUMP_PATH");
        int maxMatches = parseMaxMatches(System.getenv("REREVVED_MAX_MATCHES"));
        ReferenceManager references = currentProgram.getReferenceManager();
        int matches = 0;

        try (PrintWriter out = new PrintWriter(new FileWriter(outPath))) {
            out.println("Program: " + currentProgram.getName());
            out.println("Terms: " + String.join(",", terms));
            DefinedDataIterator strings = DefinedDataIterator.byDataInstance(
                currentProgram, Data::hasStringValue);
            while (strings.hasNext()) {
                Data data = strings.next();
                if (monitor.isCancelled() || matches >= maxMatches) {
                    break;
                }
                Object value = data.getValue();
                if (!(value instanceof String)) {
                    continue;
                }
                String text = (String) value;
                String folded = text.toLowerCase(Locale.ROOT);
                if (!matchesAny(folded, terms)) {
                    continue;
                }
                long referenceCount = 0;
                ReferenceIterator iterator = references.getReferencesTo(data.getAddress());
                while (iterator.hasNext()) {
                    iterator.next();
                    referenceCount++;
                }
                out.printf("0x%08X refs=%d %s%n",
                    data.getAddress().getOffset(), referenceCount, escape(text));
                matches++;
            }
            out.println("Matches: " + matches);
        }
        println("WROTE: " + outPath);
    }

    private boolean matchesAny(String text, List<String> terms) {
        for (String term : terms) {
            if (text.contains(term)) {
                return true;
            }
        }
        return false;
    }

    private List<String> parseTerms(String value) {
        List<String> terms = new ArrayList<>();
        for (String token : value.split(",")) {
            String term = token.trim().toLowerCase(Locale.ROOT);
            if (!term.isEmpty()) {
                terms.add(term);
            }
        }
        if (terms.isEmpty()) {
            throw new IllegalArgumentException("REREVVED_STRING_TERMS is empty");
        }
        return terms;
    }

    private int parseMaxMatches(String value) {
        int maxMatches = value == null || value.isBlank() ? 200 : Integer.parseInt(value);
        if (maxMatches < 1 || maxMatches > 1000) {
            throw new IllegalArgumentException("REREVVED_MAX_MATCHES must be 1 through 1000");
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
