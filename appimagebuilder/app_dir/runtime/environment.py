#  Copyright  2021 Alexis Lopez Zubieta
#
#  Permission is hereby granted, free of charge, to any person obtaining a
#  copy of this software and associated documentation files (the "Software"),
#  to deal in the Software without restriction, including without limitation the
#  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#  sell copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.


class Environment:
    def __init__(self):
        self._env = dict()

    def __contains__(self, item):
        return item in self._env

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

    def items(self):
        return self._env.items()

    @staticmethod
    def serialize(env: dict):
        lines = []
        for k, v in env.items():
            if isinstance(v, str):
                lines.append("%s=%s\n" % (k, v))

            if isinstance(v, list):
                if k == "EXEC_ARGS":
                    lines.append("%s=%s\n" % (k, " ".join(v)))
                else:
                    lines.append("%s=%s\n" % (k, ":".join(v)))

            if isinstance(v, dict):
                entries = ["%s:%s;" % (k, v) for (k, v) in v.items()]
                lines.append("%s=%s\n" % (k, "".join(entries)))

        result = "".join(lines)
        return result


class GlobalEnvironment(Environment):
    """
    Represents the global execution environment of the bundle
    """


class ExecutableEnvironment(Environment):
    """
    Holds the execution environment of a given executable
    """

    pass
