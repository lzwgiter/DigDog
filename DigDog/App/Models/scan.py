# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'scan.ui'
#
# Created by: PyQt5 UI code generator 5.9
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets


class DigdogReport(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(700, 500)
        MainWindow.setMinimumSize(QtCore.QSize(700, 500))
        MainWindow.setMaximumSize(QtCore.QSize(700, 500))
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(245, 20, 281, 61))
        font = QtGui.QFont()
        font.setFamily("华文中宋")
        font.setPointSize(38)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(70, 390, 221, 51))
        font = QtGui.QFont()
        font.setFamily("华文宋体")
        font.setPointSize(18)
        self.pushButton.setFont(font)
        self.pushButton.setCursor(QtGui.QCursor(QtCore.Qt.OpenHandCursor))
        self.pushButton.setObjectName("pushButton")
        self.pushButton_2 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_2.setGeometry(QtCore.QRect(390, 390, 221, 51))
        font = QtGui.QFont()
        font.setFamily("华文中宋")
        font.setPointSize(18)
        self.pushButton_2.setFont(font)
        self.pushButton_2.setCursor(QtGui.QCursor(QtCore.Qt.OpenHandCursor))
        self.pushButton_2.setObjectName("pushButton_2")
        font = QtGui.QFont()
        font.setFamily("华文中宋")
        font.setPointSize(12)
        self.comboBox_2 = QtWidgets.QComboBox(self.centralwidget)
        self.comboBox_2.setGeometry(QtCore.QRect(60, 100, 221, 21))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.comboBox_2.setFont(font)
        self.comboBox_2.setObjectName("comboBox_2")
        for i in range(60):
            self.comboBox_2.addItem("")
        self.checkBox = QtWidgets.QCheckBox(self.centralwidget)
        self.checkBox.setGeometry(QtCore.QRect(390, 100, 141, 16))
        font = QtGui.QFont()
        font.setFamily("华文中宋")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.checkBox.setFont(font)
        self.checkBox.setObjectName("checkBox")
        self.checkBox_2 = QtWidgets.QCheckBox(self.centralwidget)
        self.checkBox_2.setGeometry(QtCore.QRect(490, 100, 131, 16))
        font = QtGui.QFont()
        font.setFamily("华文中宋")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.checkBox_2.setFont(font)
        self.checkBox_2.setObjectName("checkBox_2")
        self.toolButton = QtWidgets.QToolButton(self.centralwidget)
        self.toolButton.setGeometry(QtCore.QRect(490, 130, 151, 30))
        font = QtGui.QFont()
        font.setFamily("华文中宋")
        font.setPointSize(12)
        self.toolButton.setFont(font)
        self.toolButton.setObjectName("toolButton")
        self.lineEdit = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit.setGeometry(QtCore.QRect(60, 130, 371, 30))
        font = QtGui.QFont()
        font.setFamily("华文中宋")
        font.setPointSize(12)
        self.lineEdit.setFont(font)
        self.lineEdit.setObjectName("lineEdit")
        self.textBrowser = QtWidgets.QTextBrowser(self.centralwidget)
        self.textBrowser.setGeometry(QtCore.QRect(60, 200, 581, 171))
        self.textBrowser.viewport().setProperty("cursor", QtGui.QCursor(QtCore.Qt.IBeamCursor))
        self.textBrowser.setObjectName("textBrowser")
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(-40, -30, 741, 511))
        font = QtGui.QFont()
        font.setFamily("华文中宋")
        font.setPointSize(12)
        self.label_3.setFont(font)
        self.label_3.setStyleSheet("image: url(:/newPrefix/nbg.jpg);")
        self.label_3.setText("")
        self.label_3.setObjectName("label_3")
        self.lineEdit_2 = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_2.setGeometry(QtCore.QRect(60, 165, 371, 30))
        font = QtGui.QFont()
        font.setFamily("华文中宋")
        font.setPointSize(12)
        self.lineEdit_2.setFont(font)
        self.lineEdit_2.setObjectName("textEdit_2")
        self.toolButton_2 = QtWidgets.QToolButton(self.centralwidget)
        self.toolButton_2.setGeometry(QtCore.QRect(490, 165, 151, 30))
        font = QtGui.QFont()
        font.setFamily("华文中宋")
        font.setPointSize(12)
        self.toolButton_2.setFont(font)
        self.toolButton_2.setObjectName("toolButton_2")
        self.label_3.raise_()
        self.label.raise_()
        self.pushButton.raise_()
        self.pushButton_2.raise_()
        self.comboBox_2.raise_()
        self.checkBox.raise_()
        self.checkBox_2.raise_()
        self.toolButton.raise_()
        self.lineEdit.raise_()
        self.textBrowser.raise_()
        self.lineEdit_2.raise_()
        self.toolButton_2.raise_()
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 700, 31))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "扫描与报告"))
        self.label.setText(_translate("MainWindow", "扫描与报告"))
        self.pushButton.setText(_translate("MainWindow", "← 返回"))
        self.pushButton_2.setText(_translate("MainWindow", "运行"))
        self.comboBox_2.setItemText(0, _translate("MainWindow", "Win10x64_10240_17770"))
        self.comboBox_2.setItemText(1, _translate("MainWindow", "Win10x86_10240_17770"))
        self.comboBox_2.setItemText(2, _translate("MainWindow", "VistaSP0x64"))
        self.comboBox_2.setItemText(3, _translate("MainWindow", "VistaSP0x86"))
        self.comboBox_2.setItemText(4, _translate("MainWindow", "VistaSP1x64"))
        self.comboBox_2.setItemText(5, _translate("MainWindow", "VistaSP1x86"))
        self.comboBox_2.setItemText(6, _translate("MainWindow", "VistaSP2x64"))
        self.comboBox_2.setItemText(7, _translate("MainWindow", "VistaSP2x86"))
        self.comboBox_2.setItemText(8, _translate("MainWindow", "Win10x64"))
        self.comboBox_2.setItemText(9, _translate("MainWindow", "Win10x64_10586"))
        self.comboBox_2.setItemText(10, _translate("MainWindow", "Win10x64_14393"))
        self.comboBox_2.setItemText(11, _translate("MainWindow", "Win10x64_15063"))
        self.comboBox_2.setItemText(12, _translate("MainWindow", "Win10x64_16299"))
        self.comboBox_2.setItemText(13, _translate("MainWindow", "Win10x64_17134"))
        self.comboBox_2.setItemText(14, _translate("MainWindow", "Win10x64_17736"))
        self.comboBox_2.setItemText(15, _translate("MainWindow", "Win10x64_18362"))
        self.comboBox_2.setItemText(16, _translate("MainWindow", "Win10x86"))
        self.comboBox_2.setItemText(17, _translate("MainWindow", "Win10x86_10586"))
        self.comboBox_2.setItemText(18, _translate("MainWindow", "Win10x86_14393"))
        self.comboBox_2.setItemText(19, _translate("MainWindow", "Win10x86_15063"))
        self.comboBox_2.setItemText(20, _translate("MainWindow", "Win10x86_16299"))
        self.comboBox_2.setItemText(21, _translate("MainWindow", "Win10x86_17134"))
        self.comboBox_2.setItemText(22, _translate("MainWindow", "Win10x86_17763"))
        self.comboBox_2.setItemText(23, _translate("MainWindow", "Win10x86_18362"))
        self.comboBox_2.setItemText(24, _translate("MainWindow", "WinXPSP1x64"))
        self.comboBox_2.setItemText(25, _translate("MainWindow", "WinXPSP2x64"))
        self.comboBox_2.setItemText(26, _translate("MainWindow", "WinXPSP2x86"))
        self.comboBox_2.setItemText(27, _translate("MainWindow", "WinXPSP3x86"))
        self.comboBox_2.setItemText(28, _translate("MainWindow", "Win2003SP0x86"))
        self.comboBox_2.setItemText(29, _translate("MainWindow", "Win2003SP1x64"))
        self.comboBox_2.setItemText(30, _translate("MainWindow", "Win2003SP1x86"))
        self.comboBox_2.setItemText(31, _translate("MainWindow", "Win2003SP2x64"))
        self.comboBox_2.setItemText(32, _translate("MainWindow", "Win2003SP2x86"))
        self.comboBox_2.setItemText(33, _translate("MainWindow", "Win2008R2SP0x64"))
        self.comboBox_2.setItemText(34, _translate("MainWindow", "Win2008R2SP1x64"))
        self.comboBox_2.setItemText(35, _translate("MainWindow", "Win2008R2SP0x64_23418"))
        self.comboBox_2.setItemText(36, _translate("MainWindow", "Win2008R2SP1x64_24000"))
        self.comboBox_2.setItemText(37, _translate("MainWindow", "Win2008SP1x64"))
        self.comboBox_2.setItemText(38, _translate("MainWindow", "Win2008SP1x86"))
        self.comboBox_2.setItemText(39, _translate("MainWindow", "Win2008SP2x64"))
        self.comboBox_2.setItemText(40, _translate("MainWindow", "Win2008SP2x86"))
        self.comboBox_2.setItemText(41, _translate("MainWindow", "Win2012R2x64"))
        self.comboBox_2.setItemText(42, _translate("MainWindow", "Win2012R2x64_18340"))
        self.comboBox_2.setItemText(43, _translate("MainWindow", "Win2012x64"))
        self.comboBox_2.setItemText(44, _translate("MainWindow", "Win2012x64_14393"))
        self.comboBox_2.setItemText(45, _translate("MainWindow", "Win7SP0x64"))
        self.comboBox_2.setItemText(46, _translate("MainWindow", "Win7SP0x86"))
        self.comboBox_2.setItemText(47, _translate("MainWindow", "Win7SP1x64"))
        self.comboBox_2.setItemText(48, _translate("MainWindow", "Win7SP1x86"))
        self.comboBox_2.setItemText(49, _translate("MainWindow", "Win7SP1x64_23418"))
        self.comboBox_2.setItemText(50, _translate("MainWindow", "Win7SP1x86_23418"))
        self.comboBox_2.setItemText(51, _translate("MainWindow", "Win7SP1x64_24000"))
        self.comboBox_2.setItemText(52, _translate("MainWindow", "Win7SP1x86_24000"))
        self.comboBox_2.setItemText(53, _translate("MainWindow", "Win81U1x64"))
        self.comboBox_2.setItemText(54, _translate("MainWindow", "Win81U1x86"))
        self.comboBox_2.setItemText(55, _translate("MainWindow", "Win8SP0x64"))
        self.comboBox_2.setItemText(56, _translate("MainWindow", "Win8SP0x86"))
        self.comboBox_2.setItemText(57, _translate("MainWindow", "Win8SP1x64"))
        self.comboBox_2.setItemText(58, _translate("MainWindow", "Win8SP1x86"))
        self.comboBox_2.setItemText(59, _translate("MainWindow", "Win8SP1x64_18340"))
        self.checkBox.setText(_translate("MainWindow", "malfind"))
        self.checkBox_2.setText(_translate("MainWindow", "hollowfind"))
        self.toolButton.setText(_translate("MainWindow", "选择内存文件"))
        self.toolButton_2.setText(_translate("MainWindow", "选择json文件"))
        self.lineEdit.setText(_translate("MainWindow", "内存文件"))
        self.lineEdit_2.setText(_translate("MainWindow", "模型描述json文件"))
        self.textBrowser.setHtml(_translate("MainWindow",
                                            "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
                                            "<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
                                            "p, li { white-space: pre-wrap; }\n"
                                            "</style></head><body style=\" font-family:\'Ubuntu\'; font-size:11pt; font-weight:400; font-style:normal;\">\n"
                                            "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-family:\'SimSun\'; font-size:9pt;\"></span></p></body></html>"))


import bg_rc
