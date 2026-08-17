# Evidence model

Retail guest data is authoritative. Ghidra, generated C++, runtime logs, and
external source material are tools for interpreting it. None is independently
a correctness oracle.

Every promoted finding should carry:

- the source image SHA-256 or a manifest reference to it;
- exact guest addresses and offsets;
- the narrow claim supported by the evidence;
- confidence: `confirmed`, `strong`, `candidate`, or `rejected`;
- static and dynamic evidence locators when behavior is claimed;
- unresolved alternatives or a falsification condition.

Raw decompilation is scratch output. Preserve names, addresses, signatures,
field layouts, call relationships, and short behavioral summaries instead of
copying function bodies.

Consumers promote facts explicitly and then own their copy. This repository
must never become a sibling-path build dependency.
