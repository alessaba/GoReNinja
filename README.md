# GoReNinja

Go reversing toolkit for Binary Ninja: function recovery, type and interface reconstruction, build information, and IL-aware decompilation improvements.

## Attribution

GoReNinja is a substantially expanded fork of [GoLang binary parser](https://github.com/dipusone/golang_pclntab_parser), originally created by **Jacopo Ferrigno** and distributed under the MIT license. The original copyright and license are preserved in `LICENSE` and `NOTICE`. Subsequent development is by the GoReNinja contributors.

## Installation

Clone the repository into Binary Ninja's plugin directory and restart Binary Ninja:

```sh
git clone https://github.com/alessaba/GoReNinja.git
```

Alternatively, install it as a local plugin by placing this directory in your user plugin folder. The plugin is named **GoReNinja** in `plugin.json`; its commands remain under the `golang` menu for now.

## Features

- Function names from the `.gopclntab` section. If the section is missing or named differently, the plugin searches for the pclntab magic in the binary.
- Function comments with the source file (and line, when enabled) the function was compiled from.
- Go type recovery, both as annotated Go types and, optionally, as native Binary Ninja types.
- Optional typelink enumeration to recover types that are not referenced by the analyzed code, including the serialized `__go_type` descriptor region used by Go 1.27+.
- Optional interface recovery on top of the type recovery, using `__itablink`/`.itablink` on older binaries and the Go 1.27 contiguous itab range.
- Decompiler enhancement after the type recovery: Go runtime and method prototypes are applied persistently to the recovered functions, and the IL is annotated with the Go allocation, panic, `defer` and memory idioms.
- IL-aware type discovery through MLIL call/tailcall parameters with an HLIL fallback when MLIL is unavailable.
- Go build info (release and module information) and the list of source files included in the binary.
- GoReSym integration: import an existing JSON output or run GoReSym and import its output, including both user and standard-library functions.

## Workflow

Run `golang\Parse Go binary` to execute the whole pipeline: it logs the build info, renames the functions, comments them, recovers the types, recovers the interfaces and finally applies the decompiler enhancement. Each step runs in its own background task and the next one starts only when the previous one has finished.

Individual steps are available as separate commands when only part of the information is needed.

## Commands

| Command | Description |
| --- | --- |
| `golang\Parse Go binary` | Full pipeline: build info, function rename, function comments, type recovery, interface recovery and decompiler enhancement, according to the settings. |
| `golang\Recover functions` | Rename the Go functions and optionally comment them with their source file. |
| `golang\Recover Go types` | Recover the Go types (or the native Binary Ninja types), optionally the interfaces, and apply the decompiler enhancement. |
| `golang\Recover Go type at address` | Recover the type at the current address, as Go or native Binary Ninja types. |
| `golang\GoReSym\Import JSON...` | Import function information from a GoReSym JSON file and restore the Go version magic. |
| `golang\GoReSym\Run and import` | Run GoReSym, import its output and restore the Go version magic. |
| `golang\Utilities\Show build info and source files` | Log the Go build info and the list of files included in the binary. |

## Settings

| Setting | Default | Description |
| --- | --- | --- |
| `golang_binary_parser.components` | `true` | Organize the renamed functions in components. |
| `golang_binary_parser.sanitize` | `false` | Remove `.` and spaces from function and type names, so they do not need backticks. |
| `golang_binary_parser.minimum_name_length` | `2` | Rename a function only if the recovered name is longer than this value. |
| `golang_binary_parser.goresym_path` | `GoReSym` | Full path of GoReSym, if it is not in `$PATH`. |
| `golang_binary_parser.recover_native_types` | `false` | Use the native Binary Ninja type recovery instead of the Go type recovery in the type commands and in the full pipeline. |
| `golang_binary_parser.comment_functions` | `true` | Add source file comments in `Recover functions` and in the full pipeline. |
| `golang_binary_parser.source_lines` | `true` | Include the line number in the source file comments. |
| `golang_binary_parser.use_typelinks` | `true` | Enumerate types from typelinks: more types are found, but the recovery is slower. |
| `golang_binary_parser.recover_interfaces` | `true` | Recover interface information in `Recover Go types` and in the full pipeline. |
| `golang_binary_parser.recover_prototypes` | `true` | Apply the recovered Go runtime and method prototypes to the functions during the decompiler enhancement. |
| `golang_binary_parser.decompiler_annotations` | `true` | Add IL-aware comments for the Go allocation, panic, `defer` and memory idioms during the decompiler enhancement. |

## Version notes

- The `pclntab` layouts 1.2, 1.16, 1.18 and 1.20+ are supported.
- Type recovery relies on the runtime type metadata and is best tested on Go 1.16 and newer binaries. Older `__typelink`/`.typelink` tables and Go 1.27's serialized `__go_type`/`.go.type` descriptors and contiguous itabs are supported.
- Native type recovery and interface recovery are optional: the default setup produces annotated Go types and also recovers interfaces.
- The decompiler enhancement applies prototypes and comments only: no speculative Go register-ABI rewrite of parameters or call sites is performed.
- Non-Go binaries and binaries without a recognizable `pclntab` are reported in the log instead of aborting the whole pipeline.

## Tests

The test suite uses synthetic Binary Ninja stubs and does not require a license or UI:

```sh
python3 -B -m unittest discover -s tests -p 'test_*.py'
```

## References

The plugin is based on the following resources.

	https://github.com/f0rki/bn-goloader
	https://go.dev/src/debug/gosym/pclntab.go
	https://docs.google.com/document/d/1lyPIbmsYbXnpNj57a261hgOYVpNRcgydurVQIyZOz_o/pub
	https://securelist.com/extracting-type-information-from-go-binaries/104715/
	https://github.com/golang/go/blob/fad4a16fd43f6a72b6917eff656be27522809074/src/reflect/type.go#L317


## Contributors

- [ltlly](https://github.com/ltlly)

## License

This plugin is released under an [MIT license](./license).
