#  Copyright  2019 Alexis Lopez Zubieta
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
import fileinput


def make_links_relative_to_root(root_dir):
    for root, dirs, files in os.walk(root_dir):
        for filename in files:
            absolute_path = os.path.join(root, filename)
            if os.path.islink(absolute_path):
                link_target = os.readlink(absolute_path)
                if link_target.startswith("/"):
                    make_link_relative(root_dir, absolute_path, link_target)


def make_link_relative(root_dir, absolute_path, link_target):
    absolute_new_link_target = root_dir + link_target

    folder_path = os.path.dirname(absolute_path)

    new_link_target = os.path.relpath(absolute_new_link_target, folder_path)

    os.unlink(absolute_path)

    os.symlink(new_link_target, absolute_path)

    print("making link relative: %s %s " % (absolute_path, new_link_target))


def remove_files(regexp):
    pass


def replace_in_file(file, text_to_search, replacement_text):
    with fileinput.FileInput(file, inplace=True, mode="rb") as file:
        for line in file:
            print(line.replace(text_to_search, replacement_text), end='')
