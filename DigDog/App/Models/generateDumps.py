# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'generateDumps.ui'
#
# Created by: PyQt5 UI code generator 5.9
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets


class DigdogGenerateDumps(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(700, 500)
        MainWindow.setMinimumSize(QtCore.QSize(700, 500))
        MainWindow.setMaximumSize(QtCore.QSize(700, 500))
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(70, 400, 161, 41))
        font = QtGui.QFont()
        font.setFamily("华文中宋")
        font.setPointSize(18)
        self.pushButton.setFont(font)
        self.pushButton.setObjectName("pushButton")
        self.pushButton_2 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_2.setGeometry(QtCore.QRect(280, 400, 161, 41))
        font = QtGui.QFont()
        font.setFamily("华文中宋")
        font.setPointSize(18)
        self.pushButton_2.setFont(font)
        self.pushButton_2.setObjectName("pushButton_2")
        self.pushButton_3 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_3.setGeometry(QtCore.QRect(480, 400, 161, 41))
        font = QtGui.QFont()
        font.setFamily("华文中宋")
        font.setPointSize(18)
        self.pushButton_3.setFont(font)
        self.pushButton_3.setObjectName("pushButton_3")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(245, 15, 451, 61))
        font = QtGui.QFont()
        font.setFamily("华文中宋")
        font.setPointSize(38)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.textBrowser = QtWidgets.QTextBrowser(self.centralwidget)
        self.textBrowser.setGeometry(QtCore.QRect(60, 210, 571, 171))
        self.textBrowser.setObjectName("textBrowser")
        self.pushButton_4 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_4.setGeometry(QtCore.QRect(440, 150, 191, 30))
        font = QtGui.QFont()
        font.setFamily("华文中宋")
        font.setPointSize(14)
        self.pushButton_4.setFont(font)
        self.pushButton_4.setObjectName("pushButton_4")
        self.toolButton_2 = QtWidgets.QToolButton(self.centralwidget)
        self.toolButton_2.setGeometry(QtCore.QRect(440, 90, 191, 30))
        font = QtGui.QFont()
        font.setFamily("华文中宋")
        font.setPointSize(14)
        self.toolButton_2.setFont(font)
        self.toolButton_2.setObjectName("toolButton_2")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(-50, 0, 761, 461))
        self.label_2.setStyleSheet("image: url(:/newPrefix/nbg.jpg);")
        self.label_2.setText("")
        self.label_2.setObjectName("label_2")
        self.lineEdit = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit.setGeometry(QtCore.QRect(60, 150, 371, 30))
        font = QtGui.QFont()
        font.setFamily("华文中宋")
        font.setPointSize(12)
        self.lineEdit.setFont(font)
        self.lineEdit.setObjectName("lineEdit")
        self.lineEdit_2 = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_2.setGeometry(QtCore.QRect(60, 90, 371, 30))
        font = QtGui.QFont()
        font.setFamily("华文中宋")
        font.setPointSize(12)
        self.lineEdit_2.setFont(font)
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.label_2.raise_()
        self.pushButton.raise_()
        self.pushButton_2.raise_()
        self.pushButton_3.raise_()
        self.label.raise_()
        self.textBrowser.raise_()
        self.pushButton_4.raise_()
        self.toolButton_2.raise_()
        self.lineEdit.raise_()
        self.lineEdit_2.raise_()
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
        MainWindow.setWindowTitle(_translate("MainWindow", "生成内存 - 生成用以分析的内存转储文件"))
        self.pushButton.setText(_translate("MainWindow", "← 返回"))
        self.pushButton_2.setText(_translate("MainWindow", "菜单"))
        self.pushButton_3.setText(_translate("MainWindow", "下一步 →"))
        self.label.setText(_translate("MainWindow", "生成内存"))
        self.textBrowser.setHtml(_translate("MainWindow",
                                            "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
                                            "<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
                                            "p, li { white-space: pre-wrap; }\n"
                                            "</style></head><body style=\" font-family:\'Ubuntu\'; font-size:11pt; font-weight:400; font-style:normal;\">\n"
                                            "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-family:\'SimSun\'; font-size:9pt;\"><b>Logging:</b></span></p></br></body></html>"))
        self.pushButton_4.setText(_translate("MainWindow", "运行"))
        self.toolButton_2.setText(_translate("MainWindow", "选择储存路径"))
        self.lineEdit.setText(_translate("MainWindow", "数据库名称"))
        self.lineEdit_2.setText(_translate("MainWindow", "储存路径"))

import bg_rc
