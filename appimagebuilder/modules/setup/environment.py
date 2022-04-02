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

    def __getitem__(self, item):
        return self._env[item]

    def __setitem__(self, key, value):
        self._env[key] = value

    def __delitem__(self, key):
        del self._env[key]

    def __delattr__(self, item):
        del self._env[item]

    def set(self, key, value):
        self._env[key] = value

    def get(self, key):
        if key not in self._env:
            raise RuntimeError("Environment '%s' required but not found" % key)
        return self._env[key]

    def keys(self):
        return self._env.keys()

    def append(self, key, value):
        if key in self._env and self._env[key]:
            self._env[key].append(value)
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
            lines.append(self._serialize_entry(k, v))

        lines = [line + "\n" for line in lines]
        return "".join(lines)

    def _serialize_entry(self, k, v):
        if k == "APPDIR_EXEC_ARGS" and isinstance(v, list):
            return self._serialize_list(k, v, " ")

        if k == "APPDIR_PATH_MAPPINGS":
            return self._serialize_list(k, v, ";") + ";"

        if isinstance(v, list):
            return self._serialize_list(k, v, ":")

        if isinstance(v, dict):
            entries = ["%s:%s;" % (k, v) for (k, v) in v.items()]
            entries_str = "".join(entries)
            return f"{k}={entries_str}"

        if v is None:
            return f'{k}=""'

        return f"{k}={v}"

    def _serialize_list(self, k, values, separator):
        values_str = separator.join(values)
        return f"{k}={values_str}"
