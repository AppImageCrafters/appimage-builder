import os


class Config:
    def __init__(self, recipe):
        self.recipe = recipe

        self.app_dir = os.path.abspath(self.recipe.get_item('AppDir/path'))

        self.arch = self.recipe.get_item('AppDir/yum/arch')
        self.include_list = self.recipe.get_item('AppDir/yum/include')
        self.exclude_list = self.recipe.get_item('AppDir/yum/exclude', [])

        self.cache_root = self._get_cache_dir()
        self.archives_path = self._get_archives_path()

    def configure(self):
        os.makedirs(self.cache_root, exist_ok=True)
        os.makedirs(self.archives_path, exist_ok=True)

    def _get_cache_dir(self):
        return os.path.abspath('appimage-builder-cache')

    def _get_archives_path(self):
        return os.path.join(self.cache_root, 'yum', 'archives')
