from binaryninja import PluginCommand, Settings

from .parsers import (
    parse_go_binary,
    recover_functions,
    recover_go_types,
    recover_go_type_at_address,
    goresym_import,
    goresym_run_and_import,
    show_build_info_and_source_files
)

PluginCommand.register(
    "golang\\Parse Go binary",
    "Parse the Go binary: recover build info, functions, comments, types and interfaces according to the settings",
    parse_go_binary)

PluginCommand.register(
    "golang\\Recover functions",
    "Automatically recover and rename go functions based on information from gopclntab",
    recover_functions)

PluginCommand.register(
    "golang\\Recover Go types",
    "Parse the file, recover and create the go types definition",
    recover_go_types)

PluginCommand.register_for_address(
    "golang\\Recover Go type at address",
    "Parse the current address, recover and create the go types definition",
    recover_go_type_at_address)

PluginCommand.register(
    "golang\\GoReSym\\Import JSON...",
    "Import information from GoReSym and restore the go version magic",
    goresym_import)

PluginCommand.register(
    "golang\\GoReSym\\Run and import",
    "Run GoReSym, import the information and restore the go version magic",
    goresym_run_and_import)

PluginCommand.register(
    "golang\\Utilities\\Show build info and source files",
    "Log the Go build info and the list of files that were included in the Go binary",
    show_build_info_and_source_files)


def setup_plugin_settings():
    settings = Settings()
    settings.register_group('golang_binary_parser', 'GoReNinja')
    Settings().register_setting("golang_binary_parser.components", """
        {
            "title" : "Organize in Components",
            "type" : "boolean",
            "default" : true,
            "description" : "Whether to organize the functions recovered in components or not",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
        }
        """)

    Settings().register_setting("golang_binary_parser.sanitize", """
        {
            "title" : "Sanitize names",
            "type" : "boolean",
            "default" : false,
            "description" : "Whether to remove . and spaces from the functions and type names (if you do not like using backticks)",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
        }
        """)

    Settings().register_setting("golang_binary_parser.minimum_name_length", """
        {
            "title" : "Function name minimum length",
            "type" : "number",
            "default" : 2,
            "description" : "Rename functions only if the their name length is greater then the value set",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
        }
        """)

    Settings().register_setting("golang_binary_parser.goresym_path", """
        {
            "title" : "GoReSym path",
            "type" : "string",
            "default" : "GoReSym",
            "description" : "Full path of GoReSym if it is not in your $PATH",
            "uiSelectionAction" : "file",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
        }
        """)

    Settings().register_setting("golang_binary_parser.recover_native_types", """
        {
            "title" : "Recover native types",
            "type" : "boolean",
            "default" : false,
            "description" : "Whether to recover native Binary Ninja types instead of Go types",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
        }
        """)

    Settings().register_setting("golang_binary_parser.comment_functions", """
        {
            "title" : "Comment functions",
            "type" : "boolean",
            "default" : true,
            "description" : "Whether to comment functions with the source file where they were defined",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
        }
        """)

    Settings().register_setting("golang_binary_parser.source_lines", """
        {
            "title" : "Source line numbers in comments",
            "type" : "boolean",
            "default" : true,
            "description" : "Whether source file comments also include the line number",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
        }
        """)

    Settings().register_setting("golang_binary_parser.use_typelinks", """
        {
            "title" : "Use typelinks",
            "type" : "boolean",
            "default" : true,
            "description" : "Whether to enumerate types from typelinks, which finds more types but is slower",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
        }
        """)

    Settings().register_setting("golang_binary_parser.recover_interfaces", """
        {
            "title" : "Recover interfaces",
            "type" : "boolean",
            "default" : true,
            "description" : "Whether to recover interface information after the type recovery",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
        }
        """)

    Settings().register_setting("golang_binary_parser.recover_prototypes", """
        {
            "title" : "Recover prototypes",
            "type" : "boolean",
            "default" : true,
            "description" : "Whether to apply the recovered Go runtime and method prototypes to the functions during the decompiler enhancement",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
        }
        """)

    Settings().register_setting("golang_binary_parser.decompiler_annotations", """
        {
            "title" : "Decompiler annotations",
            "type" : "boolean",
            "default" : true,
            "description" : "Whether to add IL-aware comments for Go allocation, panic, defer and memory idioms during the decompiler enhancement",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
        }
        """)


setup_plugin_settings()
