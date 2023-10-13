# appimage-builder

*GNU/Linux packaging made easy!* ™

## What is it?

It's a tool for packing applications along with all of its dependencies using the system package manager to obtain binaries and resolve dependencies. It creates a **self-sufficient** and **portable** bundle using the [AppImage](https://appimage.org) format.

Features:
- Real GNU/Linux packaging. (no more distro packaging)
- Simple recipes.
- Simple workflow.
- Backward and forward compatibility.
- One binary, many target systems.


## Useful links

- [Installation](https://appimage-builder.readthedocs.io/en/latest/intro/install.html)
- [Getting help](https://appimage-builder.readthedocs.io/en/latest/index.html#getting-help)
- [Tutorial](https://appimage-builder.readthedocs.io/en/latest/intro/tutorial.html)
- [Documentation](https://appimage-builder.readthedocs.io)


## Projects using appimage-builder

[![Zeal](https://raw.githubusercontent.com/zealdocs/zeal/master/assets/freedesktop/128-apps-zeal.png)](https://github.com/zealdocs/zeal/)
[![Kstars](https://invent.kde.org/education/kstars/-/raw/master/logo.png)](https://invent.kde.org/education/kstars)
[![Glimpse](https://raw.githubusercontent.com/glimpse-editor/Glimpse/dev-g210/icons/Color/128/glimpse-icon.png)](https://github.com/glimpse-editor/Glimpse)
[![MystiQ](https://raw.githubusercontent.com/swl-x/MystiQ/master/icons/mystiq_128x128.png)](https://github.com/swl-x/MystiQ)
[![MAUI](https://invent.kde.org/uploads/-/system/group/avatar/1557/avatar.png)](https://invent.kde.org/maui)
[![Saber](https://raw.githubusercontent.com/adil192/saber/main/assets/icon/resized/icon-128x128.png)](https://github.com/adil192/saber)
[![ProtonUp-QT](https://github.com/DavidoTek/ProtonUp-Qt/blob/main/share/icons/hicolor/128x128/apps/net.davidotek.pupgui2.png)](https://davidotek.github.io/protonup-qt/#home)


## Developers

If you want to contribute, you can install this project from source like this:

(After cloning the repository)

### Requirements

This project requires python 3.8 to work!

### 1. Using pipenv

you can use [pipenv](https://pipenv.pypa.io/) (installed through pip) to simplify the process of setting up a virtual environment.

1. Create a virtual environment:

```shell
pipenv shell
```

if you do not have python 3.8 installed you can use another version like so:

```shell
pipenv shell --python path/to/python
```

2. Install the dependencies:

```shell
pipenv install
```

3. Add the current directory to the list of python modules:

```shell
export PYTHONPATH="`pwd`"
```

At this point you should be able to run appimage-builder by running `pipenv run appimagebuilder`!

### 2. Manual Installation

For those who don't want to use `pipenv` there's a `requirements.txt` file that contains all the dependencies.

Next you need to add the current directory to the list of python modules:

```shell
export PYTHONPATH="`pwd`"
```

Then you can run the project like so:

```shell
python appimagebuilder/__main__.py
```

### Notes

- This project uses the [Black](https://pypi.org/project/black/) code formatter.
