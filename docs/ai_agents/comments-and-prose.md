# Comments and prose

Deletion is the default for explanatory comments. Keep a comment only when it
records a guest-code locator, ABI or data-layout constraint, safety boundary,
tool interface, generated-output boundary, or provenance citation that names
and types cannot show.

Compress a survivor to one to three lines at the use site. Remove branch-time
narration, progress reports, agent assignments, experiment history, and comments
that only restate the next instruction.

Preserve source, reference, permission, and provenance citations verbatim.
Addresses, offsets, hashes, symbols, confidence labels, and uncertainty remain
unchanged when they carry a finding.

Runtime strings, command help, catalog fields, script metadata, and test labels
are behavior or data. Do not rewrite them as if they were comments. Generated
output belongs to its generator or canonical input and is never hand-edited for
style.

## Public prose

- Use ASCII punctuation and short declarative sentences.
- Avoid over-hyphenation. Keep hyphens in established technical terms, but
  prefer ordinary noun phrases to invented compound modifiers or long chains.
- Use semicolons sparingly. Prefer a period, comma, or short list unless a
  semicolon makes two closely related clauses materially clearer.
- Separate observations from their interpretation.
- Name the image, guest locator, and producing tool when the claim depends on
  them.
- State uncertainty directly instead of promoting a candidate name or behavior.
- Keep machine paths, private inputs, and active investigation state untracked.
- Do not date explanatory, status, progress, or change-history prose. Keep
  observation and capture times only as explicit metadata that identifies or
  bounds evidence. Preserve dates in source citations.
