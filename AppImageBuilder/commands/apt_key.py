#  Copyright  2020 Alexis Lopez Zubieta
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
from .apt_get import AptGetError
from .command import Command


class AptKeyError(AptGetError):
    pass


class AptKey(Command):
    def __init__(self):
        super().__init__('apt-key')

    def add(self, key_data, keyring_file_path):
        command = self._get_apt_key_add_command(keyring_file_path)
        self._run_with_input(command, key_data)
        if self.return_code != 0:
            raise AptKeyError('apt-key add failed')

    def _get_apt_key_add_command(self, keyring_path):
        return ["fakeroot", "apt-key", "--keyring", keyring_path, "add", "-"]
