from .common import GoHelper, log_error, log_info, log_warn


class PrintFiles(GoHelper):
    # Keep the log readable on binaries that embed thousands of source files.
    MAX_LOGGED_FILES = 1024

    def print_files(self):
        gopclntab = self.init_gopclntab()
        if gopclntab is None:
            log_error("Unable to list source files: no valid .gopclntab found")
            return

        # fileNames parses the table once; never rescan it for each file.
        file_names = [name for name in gopclntab.fileNames() if name]
        for file_name in file_names[:self.MAX_LOGGED_FILES]:
            log_info(file_name.decode('utf-8', errors='replace'))

        if not file_names:
            log_warn("The .gopclntab does not contain any source file name")
        elif len(file_names) > self.MAX_LOGGED_FILES:
            log_warn(f"Logging only the first {self.MAX_LOGGED_FILES} of "
                     f"{len(file_names)} source files")

    def run(self):
        return self.print_files()
