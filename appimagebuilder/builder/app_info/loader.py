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


class MissingConfigurationField(RuntimeError):
    pass


from appimagebuilder.builder.app_info.app_info import AppInfo


class AppInfoLoader:
    def load(self, config):
        app_info = self._read_config_fields(config)

        return app_info

    def _read_config_fields(self, recipe):
        recipe_app_info = recipe.AppDir.app_info
        app_info = AppInfo()
        app_info.id = recipe_app_info.id()
        app_info.name = recipe_app_info.name()
        app_info.version = recipe_app_info.version()
        app_info.icon = recipe_app_info.icon()
        app_info.exec = recipe_app_info.exec()
        app_info.exec_args = recipe_app_info.exec_args() or "$@"
        return app_info

    @staticmethod
    def _try_read_mandatory_config_value(config, key):
        if key in config:
            return config[key]
        else:
            raise MissingConfigurationField(key)

    @staticmethod
    def _try_read_config_value(config, key):
        return config[key] if key in config else None
