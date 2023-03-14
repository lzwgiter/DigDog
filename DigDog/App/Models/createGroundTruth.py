# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'createGroundTruth.ui'
#
# Created by: PyQt5 UI code generator 5.9
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets


class DigdogCreateGroundTruth(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(700, 500)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(40, 370, 161, 51))
        font = QtGui.QFont()
        font.setPointSize(18)
        self.pushButton.setFont(font)
        self.pushButton.setObjectName("pushButton")
        self.pushButton_2 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_2.setGeometry(QtCore.QRect(260, 370, 161, 51))
        font = QtGui.QFont()
        font.setPointSize(18)
        self.pushButton_2.setFont(font)
        self.pushButton_2.setObjectName("pushButton_2")
        self.pushButton_3 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_3.setGeometry(QtCore.QRect(490, 370, 161, 51))
        font = QtGui.QFont()
        font.setPointSize(18)
        self.pushButton_3.setFont(font)
        self.pushButton_3.setObjectName("pushButton_3")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(150, 30, 561, 61))
        font = QtGui.QFont()
        font.setFamily("华文中宋")
        font.setPointSize(38)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.toolButton = QtWidgets.QToolButton(self.centralwidget)
        self.toolButton.setGeometry(QtCore.QRect(450, 110, 201, 30))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.toolButton.setFont(font)
        self.toolButton.setObjectName("toolButton")
        self.textBrowser = QtWidgets.QTextBrowser(self.centralwidget)
        self.textBrowser.setGeometry(QtCore.QRect(70, 200, 581, 150))
        self.textBrowser.setObjectName("textBrowser")
        self.pushButton_4 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_4.setGeometry(QtCore.QRect(450, 160, 201, 31))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.pushButton_4.setFont(font)
        self.pushButton_4.setObjectName("pushButton_4")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(-30, 0, 731, 461))
        self.label_2.setStyleSheet("image: url(:/newPrefix/nbg.jpg);")
        self.label_2.setText("")
        self.label_2.setObjectName("label_2")
        self.lineEdit_3 = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_3.setGeometry(QtCore.QRect(70, 110, 371, 30))
        font = QtGui.QFont()
        font.setFamily("华文中宋")
        font.setPointSize(12)
        self.lineEdit_3.setFont(font)
        self.lineEdit_3.setObjectName("lineEdit_3")
        self.lineEdit = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit.setGeometry(QtCore.QRect(70, 160, 371, 30))
        font = QtGui.QFont()
        font.setFamily("华文中宋")
        font.setPointSize(12)
        self.lineEdit.setFont(font)
        self.lineEdit.setObjectName("lineEdit")
        self.label_2.raise_()
        self.pushButton.raise_()
        self.pushButton_2.raise_()
        self.pushButton_3.raise_()
        self.label.raise_()
        self.toolButton.raise_()
        self.textBrowser.raise_()
        self.pushButton_4.raise_()
        self.lineEdit_3.raise_()
        self.lineEdit.raise_()
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
        MainWindow.setWindowTitle(_translate("MainWindow", "创建GroundTruth - 使用yara创建GroundTruth"))
        self.pushButton.setText(_translate("MainWindow", "← 返回"))
        self.pushButton_2.setText(_translate("MainWindow", "菜单"))
        self.pushButton_3.setText(_translate("MainWindow", "下一步 →"))
        self.pushButton_4.setText(_translate("MainWindow", "运行"))
        self.label.setText(_translate("MainWindow", "创建GroundTruth"))
        self.toolButton.setText(_translate("MainWindow", "选择yara文件夹"))
        self.textBrowser.setHtml(_translate("MainWindow",
                                            "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
                                            "<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
                                            "p, li { white-space: pre-wrap; }\n"
                                            "</style></head><body style=\" font-family:\'Ubuntu\'; font-size:11pt; font-weight:400; font-style:normal;\">\n"
                                            "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-family:\'SimSun\'; font-size:9pt;\"><b>Logging:</b></span></p></br></body></html>"))
        self.lineEdit_3.setText(_translate("MainWindow", "选择文件夹(包含yara文件)"))
        self.lineEdit.setText(_translate("MainWindow", "数据库名"))


import bg_rc
