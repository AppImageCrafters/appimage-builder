# appimage-builder

`appimage-builder` allows packing applications along with all of its dependencies. It uses
traditional GNU/Linux software package tools like `apt` or `yum` to obtain binaries and resolve
dependencies creating a self-sufficient bundle. The embedded binaries are configured to be
relocatable and to interact with the rest. Finally, the whole bundle is compressed as a
`squashfs` filesystem and attached to a launcher binary using `appimagetool` making a
nice AppImage.

## Useful links

- [Getting help](https://appimage-builder.readthedocs.io/en/latest/index.html#getting-help)
- [Installation](https://appimage-builder.readthedocs.io/en/latest/intro/install.html)
- [Tutorial](https://appimage-builder.readthedocs.io/en/latest/intro/tutorial.html)
- [Documentation](https://appimage-builder.readthedocs.io)

