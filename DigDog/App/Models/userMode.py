# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'user.ui'
#
# Created by: PyQt5 UI code generator 5.9
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class DigdogUserMode(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(700, 500)
        MainWindow.setMinimumSize(QtCore.QSize(700, 500))
        MainWindow.setMaximumSize(QtCore.QSize(700, 500))
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(171, 198, 341, 61))
        font = QtGui.QFont()
        font.setFamily("华文中宋")
        font.setPointSize(17)
        self.pushButton.setFont(font)
        self.pushButton.setObjectName("pushButton")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(245, 70, 641, 51))
        font = QtGui.QFont()
        font.setFamily("华文中宋")
        font.setPointSize(38)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(-140, 0, 981, 501))
        self.label_2.setStyleSheet("image:url(:/newPrefix/nbg.jpg)")
        self.label_2.setText("")
        self.label_2.setObjectName("label_2")
        self.pushButton_2 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_2.setGeometry(QtCore.QRect(22, 381, 141, 41))
        font = QtGui.QFont()
        font.setPointSize(17)
        self.pushButton_2.setFont(font)
        self.pushButton_2.setObjectName("pushButton_2")
        self.label_2.raise_()
        self.pushButton.raise_()
        self.label.raise_()
        self.pushButton_2.raise_()
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 700, 28))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "用户模式"))
        self.pushButton.setText(_translate("MainWindow", "扫描与报告"))
        self.label.setText(_translate("MainWindow", "用户模式"))
        self.pushButton_2.setText(_translate("MainWindow", "返回"))

import bg_rc
