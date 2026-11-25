# Changelog

## 1.0.0 — GoReNinja initial release

GoReNinja is a substantially expanded fork of Jacopo Ferrigno's GoLang binary
parser, retaining the original MIT license and attribution.

### Added

- Robust pclntab discovery and parsing for Mach-O, ELF, and PE binaries.
- Function recovery with source file and line comments.
- Go build-info extraction, including PE `.data` fallback.
- Typelink and Go 1.27 serialized-descriptor type recovery.
- RELRO type, typelink, and itablink layouts.
- Interface recovery through itablinks and Go 1.27 contiguous itabs.
- IL-aware type discovery and decompiler annotations.
- Persistent runtime and interface-method prototypes.
- GoReSym user and standard-library function import.
- Seven consolidated commands and configurable recovery stages.
- 173+ unit tests and real Mach-O, ELF, PIE, and PE validation fixtures.

### Changed

- Rebranded the project as GoReNinja.
- Improved malformed-input handling, work bounds, and pipeline error reporting.
- Corrected numerous upstream type-layout and Binary Ninja API issues.
