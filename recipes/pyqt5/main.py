#!/usr/bin/env python3

import sys
from PyQt5.QtWidgets import QApplication, QLabel, QMainWindow
from PyQt5.QtCore import Qt
from PyQt5 import QtGui
from pyfiglet import Figlet


# Subclass QMainWindow to customise your application's main window
class MainWindow(QMainWindow):
    def __init__(self, *args, **kwargs):
        super(MainWindow, self).__init__(*args, **kwargs)

        self.setWindowTitle("My Awesome App")
        f = Figlet(font="digital")
        label = QLabel(f.renderText("Hello World!"))
        label.setFont(QtGui.QFont("monospace", 14, QtGui.QFont.Black))

        label.setAlignment(Qt.AlignCenter)

        self.setCentralWidget(label)


app = QApplication(sys.argv)

window = MainWindow()
window.show()

app.exec_()
