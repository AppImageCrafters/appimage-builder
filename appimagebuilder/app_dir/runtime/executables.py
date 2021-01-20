class ExecutableProcessingError(RuntimeError):
    pass


class Executable:
    """Executable unit with its environment"""

    def __init__(self, path, args: [str]):
        self.path = path
        self.args = args

    def __str__(self) -> str:
        return self.path

    def __eq__(self, o: object) -> bool:
        return (
            self.__class__ == o.__class__
            and self.path == o.path
            and self.args == o.args
        )


class InterpretedExecutable(Executable):
    """Interpreted executable of any kind"""

    def __init__(self, path, args: [str]):
        super().__init__(path, args)
        self.shebang = self.read_shebang(path)

    def __eq__(self, o: object) -> bool:
        return (
            self.__class__ == o.__class__
            and self.path == o.path
            and self.shebang == o.shebang
        )

    @staticmethod
    def read_shebang(path) -> [str]:
        with open(path, "rb") as f:
            buf = f.read(128)

            if buf[0] != ord("#") or buf[1] != ord("!"):
                raise ExecutableProcessingError(
                    "No shebang found, this file is not an script!"
                )

            end_idx = buf.find(b"\n")
            if end_idx == -1:
                end_idx = len(buf)

            buf = buf[2:end_idx].decode()

            parts = buf.split(" ")
            return parts


def search_interpreted_executables(file_cache) -> [InterpretedExecutable]:
    executables = []
    paths = file_cache.find("*", ["is_exec"])
    for path in paths:
        try:
            executables.append(InterpretedExecutable(path, []))
        except ExecutableProcessingError:
            pass
    return executables
