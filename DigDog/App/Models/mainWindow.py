# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'main.ui'
#
# Created by: PyQt5 UI code generator 5.9
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets


class DigdogMain(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(700, 500)
        MainWindow.setMinimumSize(QtCore.QSize(700, 500))
        MainWindow.setMaximumSize(QtCore.QSize(700, 500))
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(180, 290, 341, 61))
        font = QtGui.QFont()
        font.setFamily("华文中宋")
        font.setPointSize(17)
        self.pushButton.setFont(font)
        self.pushButton.setObjectName("pushButton")
        self.pushButton_3 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_3.setGeometry(QtCore.QRect(180, 180, 341, 61))
        font = QtGui.QFont()
        font.setFamily("华文中宋")
        font.setPointSize(17)
        self.pushButton_3.setFont(font)
        self.pushButton_3.setObjectName("pushButton_3")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(165, 80, 641, 70))
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
        self.label_2.raise_()
        self.pushButton.raise_()
        self.pushButton_3.raise_()
        self.label.raise_()
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 700, 28))
        self.menubar.setObjectName("menubar")
        self.menuHelp = QtWidgets.QMenu(self.menubar)
        self.menuHelp.setObjectName("menuHelp")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.actionReadMe = QtWidgets.QAction(MainWindow)
        self.actionReadMe.setObjectName("actionReadMe")
        self.actionSetting = QtWidgets.QAction(MainWindow)
        self.actionSetting.setObjectName("actionSetting")
        self.menuHelp.addAction(self.actionReadMe)
        self.menuHelp.addSeparator()
        self.menuHelp.addAction(self.actionSetting)
        self.menubar.addAction(self.menuHelp.menuAction())

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "DigDog"))
        self.pushButton.setText(_translate("MainWindow", "用户模式"))
        self.pushButton_3.setText(_translate("MainWindow", "开发者模式"))
        self.label.setText(_translate("MainWindow", "欢迎使用DigDog!"))
        self.menuHelp.setTitle(_translate("MainWindow", "帮助"))
        self.actionReadMe.setText(_translate("MainWindow", "说明"))
        self.actionSetting.setText(_translate("MainWindow", "设置 ..."))


import bg_rc
