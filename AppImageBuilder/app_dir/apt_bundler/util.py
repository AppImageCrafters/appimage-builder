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


def is_deb_file(file_name):
    return file_name.endswith('.deb')


def get_package_name_from_file_name(file_name):
    reverse_file_name = file_name[::-1]
    deb_name_parts = reverse_file_name.split('_', 2)
    reverse_package_name = deb_name_parts[2]
    return reverse_package_name[::-1]
