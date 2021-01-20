class Environment:
    def __init__(self):
        self._env = dict()

    def set(self, key, value):
        self._env[key] = value

    def get(self, key):
        if key not in self._env:
            raise RuntimeError("Environment '%s' required but not found" % key)
        return self._env[key]

    def append(self, key, value):
        if key in self._env:
            values = self._env[key]
            self._env[key] = values.append(value)
        else:
            self._env[key] = [value]


class GlobalEnvironment(Environment):
    """
    Represents the global execution environment of the bundle
    """


class ExecutableEnvironment(Environment):
    """
    Holds the execution environment of a given executable
    """

    pass
