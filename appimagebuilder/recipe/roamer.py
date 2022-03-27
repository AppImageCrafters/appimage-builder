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
import os
import re

import roam


class Roamer(roam.Roamer):
    """
    Extends the roam.Roamer class adding support for resolving environment variables.

    The Roamer class acts as a Shim over the data objects easing the access and
    traversal operations.
    """

    def __call__(
        self,
        resolve_variables=True,
        *args,
        _raise=False,
        _roam=False,
        _invoke=None,
        **kwargs
    ):
        result = super().__call__(
            *args, _raise=_raise, _roam=_roam, _invoke=_invoke, **kwargs
        )

        if resolve_variables:
            return self._resolve_variables(result)
        else:
            return result

    def __getattr__(self, attr_name):
        result = super().__getattr__(attr_name)
        return Roamer(result)

    def _resolve_variables(self, variable):
        if isinstance(variable, str):
            return self._replace_env_variables_in_str(variable)

        if isinstance(variable, list):
            new_list = []
            for v in variable:
                new_list.append(self._resolve_variables(v))
            return new_list

        if isinstance(variable, dict):
            new_dict = {}
            for k, v in variable.items():
                new_dict[k] = self._resolve_variables(v)

            return new_dict

        return variable

    def _replace_env_variables_in_str(self, variable):
        new_val = variable
        for item in re.findall(r"{{\s?\w+\s?}}", variable):
            var_name = item[2:-2]
            var_name = var_name.strip()
            if var_name not in os.environ:
                raise RuntimeError("Missing environment variable: '%s'" % var_name)
            value = os.environ[var_name]
            new_val = new_val.replace(item, value, 1)

        return new_val
