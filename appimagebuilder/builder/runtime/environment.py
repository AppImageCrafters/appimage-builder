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
    def __init__(self, values=None):
        if values:
            self._env = values
        else:
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

    def merge(self, other):
        for k, v in other.items():
            self._env[k] = v

    def drop_empty_keys(self):
        for k in list(self._env.keys()):
            if not self._env[k]:
                del self._env[k]

    def items(self):
        return self._env.items()

    def serialize(self):
        lines = []
        for k, v in self.items():
            if isinstance(v, list):
                if k == "EXEC_ARGS":
                    lines.append("%s=%s\n" % (k, " ".join(v)))
                    continue
                else:
                    lines.append("%s=%s\n" % (k, ":".join(v)))
                    continue

            if isinstance(v, dict):
                entries = ["%s:%s;" % (k, v) for (k, v) in v.items()]
                lines.append("%s=%s\n" % (k, "".join(entries)))
                continue

            if v is None:
                lines.append('%s=""\n' % (k))
                continue

            lines.append("%s=%s\n" % (k, v))

        result = "".join(lines)
        return result
