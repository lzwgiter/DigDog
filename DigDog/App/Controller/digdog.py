# !/usr/bin/python
# -*- encoding: utf-8 -*-
"""
@File    : digdog.py
@Time    : 2020/4/6 11:10
@Author  : flo@t
"""
import os
import sys
import abc
import shlex
import subprocess
from functools import partial

from PyQt5 import QtWidgets
from PyQt5.QtCore import pyqtSignal, QThread, pyqtSlot

HOME_PATH = "/".join(os.getcwd().split("/")[:-1])
BIN_PATH = "/".join(os.getcwd().split("/")[:-3]) + "/codes"

sys.path.append(HOME_PATH)
sys.path.append(BIN_PATH)

from Models.mainWindow import DigdogMain

from Models.developerMode import DigdogDeveloperMode
from Models.dataExtraction import DigdogDataExtraction
from Models.feedsamples import DigdogFeedSamples
from Models.generateDumps import DigdogGenerateDumps
from Models.createGroundTruth import DigdogCreateGroundTruth
from Models.addGroundTruth import DigdogAddGroundTruth
from Models.extractFeatures import DigdogExtractFeatures
from Models.exportRawData import DigdogExportRawData
from Models.learn import DigdogLearn
from Models.userMode import DigdogUserMode
from Models.scan import DigdogReport


class FeatureInterface(QtWidgets.QMainWindow):
    """ abstract class for all child module """

    @abc.abstractmethod
    def set_relative(self, parent=None, next=None, prev=None):
        """
        设置父窗口与同级窗口
        :param parent:
                父窗口实例
        :param next:
                同级窗口实例
        :return:
        """

    @abc.abstractmethod
    def get_args(self):
        """
        从UI界面获取参数信息
        :return:
        """

    @abc.abstractmethod
    def start_thread(self):
        """
        运行该模块对应脚本
        :return:
        """

    @abc.abstractmethod
    def setText(self, text):
        """
        将text显示在指定部件
        :param text:
           要显示的文字
        :return:
        """


class FileDialog(QtWidgets.QMainWindow):

    def __init__(self, component, output, dir=None):
        super(FileDialog, self).__init__()
        self.component = component
        if dir:
            self.component.clicked.connect(self.openDir)
        else:
            self.component.clicked.connect(self.openFile)
        self.output = output

    def openFile(self):
        file_path = QtWidgets.QFileDialog.getOpenFileName(self, "选取文件", os.getcwd(), "All Files (*)")
        self.output.setText(file_path[0])

    def openDir(self):
        dir_path = QtWidgets.QFileDialog.getExistingDirectory(self, "选择文件夹", os.getcwd())
        self.output.setText(dir_path)


class ModuleThread(QThread):
    """ 将Py文件的输出重定向至指定部件 """
    trigger = pyqtSignal(str)

    def __init__(self, args=None):
        super(ModuleThread, self).__init__()
        self.args = args

    def run(self):
        p = subprocess.Popen(self.args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        while p.poll() is None:
            line = p.stdout.readline().strip()
            self.trigger.emit(line)


class ReportInterface(FeatureInterface):
    """ Digdog Scan """

    def __init__(self):
        QtWidgets.QMainWindow.__init__(self)
        self.window = DigdogReport()
        self.window.setupUi(self)
        self.window.pushButton_2.clicked.connect(self.start_thread)
        self.fileDialog = FileDialog(self.window.toolButton, self.window.lineEdit)
        self.fileDialog_2 = FileDialog(self.window.toolButton_2, self.window.lineEdit_2)

    def set_relative(self, parent=None, next=None, prev=None):
        self.window.pushButton.clicked.connect(partial(Utils.show_upper, self, parent))

    def get_args(self):
        args = {}
        args["scan_profile"] = self.window.comboBox_2.currentText()
        args["with_malfind"] = self.window.checkBox.isChecked()
        args["with_hollowfind"] = self.window.checkBox_2.isChecked()
        dump_file_path = self.window.lineEdit.text()
        json_file_path = self.window.lineEdit_2.text()
        cmd = 'python ' + BIN_PATH + "/DigDogReport.py" + ' ' + "--custom_model " + json_file_path + ' ' + "-vp " + \
              args["scan_profile"] + ' ' + dump_file_path
        if args["with_malfind"]:
            cmd += "--with_malfind"
        elif args["with_hollowfind"]:
            cmd += "--with_hollowfind"
        cmd = shlex.split(cmd)
        return cmd

    def start_thread(self):
        thread = ModuleThread(args=self.get_args())
        thread.trigger.connect(self.setText)
        thread.start()
        thread.exec_()

    @pyqtSlot(str)
    def setText(self, text):
        self.window.textBrowser.append(text)


class LearnInterface(FeatureInterface):
    """ Digdog Learn """

    def __init__(self):
        QtWidgets.QMainWindow.__init__(self)
        self.window = DigdogLearn()
        self.window.setupUi(self)
        self.window.pushButton_2.clicked.connect(self.start_thread)
        self.fileDialog = FileDialog(self.window.toolButton, self.window.lineEdit_2)
        self.fileDialog_2 = FileDialog(self.window.toolButton_2, self.window.lineEdit_3, dir=True)

    def set_relative(self, parent=None, next=None, prev=None):
        self.window.pushButton.clicked.connect(partial(Utils.show_upper, self, parent))

    def get_args(self):
        args = {}
        args["classifier"] = self.window.comboBox_2.currentText()
        args["model_name"] = self.window.lineEdit.text()
        args["csv_file_path"] = self.window.lineEdit_2.text()
        args["model_output_path"] = self.window.lineEdit_3.text()
        cmd = shlex.split('python ' + BIN_PATH + "/DigDogLearn.py" + ' '
                          + "--classifier " + args["classifier"] + ' '
                          + "--feature_selection" + ' '
                          + args["csv_file_path"] + ' '
                          + args["model_name"] + ' '
                          + args["model_output_path"]
                          )
        return cmd

    def start_thread(self):
        thread = ModuleThread(args=self.get_args())
        thread.trigger.connect(self.setText)
        thread.start()
        thread.exec_()

    @pyqtSlot(str)
    def setText(self, text):
        self.window.textBrowser.append(text)


class DataExtractionInterface(FeatureInterface):
    """ Digdog DataExtraction """

    def __init__(self):
        QtWidgets.QMainWindow.__init__(self)
        self.window = DigdogDataExtraction()
        self.window.setupUi(self)
        self.feedSamples = self.FeedSamplesInterface()
        self.generateDumps = self.GenerateDumps()
        self.createGroundTruth = self.CreateGroundTruth()
        self.addGroundTruth = self.AddGroundTruth()
        self.extractFeatures = self.ExtractFeatures()
        self.exportRawData = self.ExportRawData()

    def set_relative(self, parent=None, next=None, prev=None):
        self.window.pushButton.clicked.connect(partial(Utils.show_upper, self, parent))
        self.window.pushButton_2.clicked.connect(partial(Utils.show_sub, self.feedSamples, self))
        self.window.pushButton_3.clicked.connect(partial(Utils.show_sub, self.generateDumps, self))
        self.window.pushButton_7.clicked.connect(partial(Utils.show_sub, self.createGroundTruth, self))
        self.window.pushButton_5.clicked.connect(partial(Utils.show_sub, self.addGroundTruth, self))
        self.window.pushButton_6.clicked.connect(partial(Utils.show_sub, self.extractFeatures, self))
        self.window.pushButton_4.clicked.connect(partial(Utils.show_sub, self.exportRawData, self))

    class FeedSamplesInterface(FeatureInterface):
        """ STEP1 feedsamples """

        def __init__(self):
            QtWidgets.QMainWindow.__init__(self)
            self.window = DigdogFeedSamples()
            self.window.setupUi(self)
            self.window.pushButton_4.clicked.connect(self.start_thread)
            self.fileDialog = FileDialog(self.window.toolButton, self.window.lineEdit)

        def set_relative(self, parent=None, next=None, prev=None):
            self.window.pushButton_2.clicked.connect(partial(Utils.show_upper, self, parent))  # menu
            self.window.pushButton.clicked.connect(partial(Utils.show_upper, self, prev))  # back
            self.window.pushButton_3.clicked.connect(partial(Utils.show_sub, next, self))  # next

        def get_args(self):
            args = {
                "sample_path": self.window.lineEdit.text(),
                "database_name": self.window.lineEdit_2.text()
            }
            if self.window.checkBox.isChecked():
                args["malicious"] = 1
            if "malicious" in args:
                cmd = shlex.split('python' + ' ' + BIN_PATH + "/DigDogDataExtraction.py" + ' '
                                  + args["database_name"] + " feedSamples" + ' '
                                  + args["sample_path"] + ' '
                                  + "malicious"
                                  )
            else:
                cmd = shlex.split('python' + ' ' + BIN_PATH + "/DigDogDataExtraction.py" + ' '
                                  + args["database_name"] + " feedSamples" + ' '
                                  + args["sample_path"] + ' '
                                  + "benign"
                                  )
            return cmd

        def start_thread(self):
            thread = ModuleThread(args=self.get_args())
            thread.trigger.connect(self.setText)
            thread.start()
            thread.exec_()

        @pyqtSlot(str)
        def setText(self, text):
            self.window.textBrowser.append(text)

    class GenerateDumps(FeatureInterface):
        """ STEP2 feedsamples """

        def __init__(self):
            QtWidgets.QMainWindow.__init__(self)
            self.window = DigdogGenerateDumps()
            self.window.setupUi(self)
            self.window.pushButton_4.clicked.connect(self.start_thread)
            self.window.fileDialog = FileDialog(self.window.toolButton_2, self.window.lineEdit_2, dir=True)

        def set_relative(self, parent=None, next=None, prev=None):
            self.window.pushButton_2.clicked.connect(partial(Utils.show_upper, self, parent))
            self.window.pushButton.clicked.connect(partial(Utils.show_upper, self, prev))
            self.window.pushButton_3.clicked.connect(partial(Utils.show_sub, next, self))

        def get_args(self):
            args = {
                "database_name": self.window.lineEdit.text(),
                "dump_file_path": self.window.lineEdit_2.text()
            }
            cmd = shlex.split('python' + ' ' + BIN_PATH + "/DigDogDataExtraction.py" + ' '
                              + args["database_name"] + " generateDumps" + ' '
                              + args["dump_file_path"]
                              )
            return cmd

        def start_thread(self):
            thread = ModuleThread(args=self.get_args())
            thread.trigger.connect(self.setText)
            thread.start()
            thread.exec_()

        @pyqtSlot(str)
        def setText(self, text):
            self.window.textBrowser.append(text)

    class CreateGroundTruth(FeatureInterface):
        """ STEP3 feedsamples """

        def __init__(self):
            QtWidgets.QMainWindow.__init__(self)
            self.window = DigdogCreateGroundTruth()
            self.window.setupUi(self)
            self.window.pushButton_4.clicked.connect(self.start_thread)
            self.window.fileDialog = FileDialog(self.window.toolButton, self.window.lineEdit_3, dir=True)

        def set_relative(self, parent=None, next=None, prev=None):
            self.window.pushButton_2.clicked.connect(partial(Utils.show_upper, self, parent))
            self.window.pushButton.clicked.connect(partial(Utils.show_upper, self, prev))
            self.window.pushButton_3.clicked.connect(partial(Utils.show_sub, next, self))

        def get_args(self):
            args = {
                "database_name": self.window.lineEdit.text(),
                "yara_path": self.window.lineEdit_3.text()
            }
            cmd = shlex.split('python' + ' ' + BIN_PATH + "/DigDogDataExtraction.py" + ' '
                              + args["database_name"] + " createGroundTruth" + ' '
                              + args["yara_path"]
                              )
            return cmd

        def start_thread(self):
            thread = ModuleThread(args=self.get_args())
            thread.trigger.connect(self.setText)
            thread.start()
            thread.exec_()

        @pyqtSlot(str)
        def setText(self, text):
            self.window.textBrowser.append(text)

    class AddGroundTruth(FeatureInterface):
        """ STEP4 feedsamples """

        def __init__(self):
            QtWidgets.QMainWindow.__init__(self)
            self.window = DigdogAddGroundTruth()
            self.window.setupUi(self)
            self.window.pushButton_4.clicked.connect(self.start_thread)
            self.window.fileDialog = FileDialog(self.window.toolButton, self.window.lineEdit)

        def set_relative(self, parent=None, next=None, prev=None):
            self.window.pushButton_2.clicked.connect(partial(Utils.show_upper, self, parent))
            self.window.pushButton.clicked.connect(partial(Utils.show_upper, self, prev))
            self.window.pushButton_3.clicked.connect(partial(Utils.show_sub, next, self))

        def get_args(self):
            args = {
                "groundTruth_path": self.window.lineEdit.text(),
                "database_name": self.window.lineEdit_2.text()
            }
            cmd = shlex.split('python' + ' ' + BIN_PATH + "/DigDogDataExtraction.py" + ' '
                              + args["database_name"] + " addGroundTruth" + ' '
                              + args["groundTruth_path"])
            return cmd

        def start_thread(self):
            thread = ModuleThread(args=self.get_args())
            thread.trigger.connect(self.setText)
            thread.start()
            thread.exec_()

        @pyqtSlot(str)
        def setText(self, text):
            self.window.textBrowser.append(text)

    class ExtractFeatures(FeatureInterface):
        """ STEP5 feedsamples """

        def __init__(self):
            QtWidgets.QMainWindow.__init__(self)
            self.window = DigdogExtractFeatures()
            self.window.setupUi(self)
            self.window.pushButton_4.clicked.connect(self.start_thread)

        def set_relative(self, parent=None, next=None, prev=None):
            self.window.pushButton_2.clicked.connect(partial(Utils.show_upper, self, parent))
            self.window.pushButton.clicked.connect(partial(Utils.show_upper, self, prev))
            self.window.pushButton_3.clicked.connect(partial(Utils.show_sub, next, self))

        def get_args(self):
            cmd = shlex.split('python' + ' ' + BIN_PATH + "/DigDogDataExtraction.py" + ' '
                              + self.window.lineEdit.text() + " extractFeatures")
            return cmd

        def start_thread(self):
            thread = ModuleThread(args=self.get_args())
            thread.trigger.connect(self.setText)
            thread.start()
            thread.exec_()

        @pyqtSlot(str)
        def setText(self, text):
            self.window.textBrowser.append(text)

    class ExportRawData(FeatureInterface):
        """ STEP6 feedsamples """

        def __init__(self):
            QtWidgets.QMainWindow.__init__(self)
            self.window = DigdogExportRawData()
            self.window.setupUi(self)
            self.window.pushButton_4.clicked.connect(self.start_thread)
            self.fileDialog = FileDialog(self.window.toolButton, self.window.lineEdit, dir=True)

        def set_relative(self, parent=None, next=None, prev=None):
            self.window.pushButton.clicked.connect(partial(Utils.show_upper, self, prev))
            self.window.pushButton_2.clicked.connect(partial(Utils.show_upper, self, parent))

        def get_args(self):
            args = {
                "csv_path": self.window.lineEdit.text(),
                "database_name": self.window.lineEdit_2.text()
            }
            cmd = shlex.split('python' + ' ' + BIN_PATH + "/DigDogDataExtraction.py" + ' '
                              + args["database_name"] + " exportRawData" + ' '
                              + args["csv_path"] + "/result.csv")
            return cmd

        def start_thread(self):
            thread = ModuleThread(args=self.get_args())
            thread.trigger.connect(self.setText)
            thread.start()
            thread.exec_()

        @pyqtSlot(str)
        def setText(self, text):
            self.window.textBrowser.append(text)


class MainInterface(QtWidgets.QMainWindow):
    """ DigDog main window """

    def __init__(self):
        QtWidgets.QMainWindow.__init__(self)
        self.window = DigdogMain()
        self.window.setupUi(self)
        self.window.actionSetting.triggered.connect(self.__open_settings)
        self.window.actionReadMe.triggered.connect(self.__open_readme)

    def set_childs(self, childs):
        self.window.pushButton.clicked.connect(partial(Utils.show_sub, childs[0], self))
        self.window.pushButton_3.clicked.connect(partial(Utils.show_sub, childs[1], self))

    @pyqtSlot()
    def __open_readme(self):
        cmd = ["evince", BIN_PATH + "/DigDog_Instruction.pdf"]
        subprocess.check_call(cmd)

    @pyqtSlot()
    def __open_settings(self):
        cmd = ["gedit", BIN_PATH + "/DigDogConfig.py"]
        subprocess.check_call(cmd)


class UserModeInterface(QtWidgets.QMainWindow):
    """ User-Mode window """

    def __init__(self):
        QtWidgets.QMainWindow.__init__(self)
        self.window = DigdogUserMode()
        self.window.setupUi(self)

    def set_relative(self, parent, childs):
        self.window.pushButton_2.clicked.connect(partial(Utils.show_upper, self, parent))
        self.__set_childs(childs)

    def __set_childs(self, childs):
        self.window.pushButton.clicked.connect(partial(Utils.show_sub, childs[0], self))


class DeveloperModeInterface(QtWidgets.QMainWindow):
    """ Developer-Mode window """

    def __init__(self):
        QtWidgets.QMainWindow.__init__(self)
        self.window = DigdogDeveloperMode()
        self.window.setupUi(self)

    def set_relative(self, parent, childs):
        self.window.pushButton_2.clicked.connect(partial(Utils.show_upper, self, parent))
        self.__set_childs(childs)

    def __set_childs(self, childs):
        self.window.pushButton.clicked.connect(partial(Utils.show_sub, childs[1], self))
        self.window.pushButton_3.clicked.connect(partial(Utils.show_sub, childs[0], self))


class Utils(object):
    """ This class use to change layer of the windows """

    @staticmethod
    def show_upper(child, parent):
        child.hide()
        parent.show()

    @staticmethod
    def show_sub(child, parent):
        parent.hide()
        child.show()


def config():
    desktop = app.desktop()
    x = (desktop.width() - main_window.width()) // 2
    y = (desktop.height() - main_window.height()) // 2

    # +++++++++++++++++++++++++++++++++++++++++++++++++
    # Moving all windows to same position to avoid sway
    main_window.move(x, y)

    user_window.move(x, y)
    report_window.move(x, y)

    dev_window.move(x, y)
    learn_window.move(x, y)
    dataExtraction_window.move(x, y)
    dataExtraction_window.feedSamples.move(x, y)
    dataExtraction_window.generateDumps.move(x, y)
    dataExtraction_window.createGroundTruth.move(x, y)
    dataExtraction_window.addGroundTruth.move(x, y)
    dataExtraction_window.extractFeatures.move(x, y)
    dataExtraction_window.exportRawData.move(x, y)
    # ++++++++++++++++++++++++++++++++++++++++++++++++++

    # ++++++++++++++++++++++++++++++++++++++++++++++++++
    # list all relationships
    main_branch = [user_window, dev_window]
    user_branch = [report_window]
    dev_branch = [dataExtraction_window, learn_window]
    # ++++++++++++++++++++++++++++++++++++++++++++++++++

    # ++++++++++++++++++++++++++++++++++++++++++++++++++
    # setting up all relationships
    main_window.set_childs(main_branch)
    user_window.set_relative(parent=main_window, childs=user_branch)
    dev_window.set_relative(parent=main_window, childs=dev_branch)

    report_window.set_relative(parent=user_window)
    learn_window.set_relative(parent=dev_window)
    dataExtraction_window.set_relative(parent=dev_window)
    # ++++++++++++++++++++++++++++++++++++++++++++++++++

    # ++++++++++++++++++++++++++++++++++++++++++++++++++
    # setting up dev_branch relationships
    dataExtraction_window.feedSamples.set_relative(parent=dataExtraction_window,
                                                   next=dataExtraction_window.generateDumps,
                                                   prev=dataExtraction_window)
    dataExtraction_window.generateDumps.set_relative(parent=dataExtraction_window,
                                                     next=dataExtraction_window.createGroundTruth,
                                                     prev=dataExtraction_window.feedSamples)
    dataExtraction_window.createGroundTruth.set_relative(parent=dataExtraction_window,
                                                         next=dataExtraction_window.addGroundTruth,
                                                         prev=dataExtraction_window.generateDumps)
    dataExtraction_window.addGroundTruth.set_relative(parent=dataExtraction_window,
                                                      next=dataExtraction_window.extractFeatures,
                                                      prev=dataExtraction_window.createGroundTruth)
    dataExtraction_window.extractFeatures.set_relative(parent=dataExtraction_window,
                                                       next=dataExtraction_window.exportRawData,
                                                       prev=dataExtraction_window.addGroundTruth)
    dataExtraction_window.exportRawData.set_relative(parent=dataExtraction_window,
                                                     prev=dataExtraction_window.extractFeatures)
    # ++++++++++++++++++++++++++++++++++++++++++++++++++


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    # Digdog main window
    main_window = MainInterface()

    # DigDogs' User-Mode window, this include `Scan and Report`
    user_window = UserModeInterface()
    # Scan and Report window
    report_window = ReportInterface()

    # DigDogs' Dev-Mode window, this include `DataExtraction and Learn`
    dev_window = DeveloperModeInterface()
    # Model-Learning window
    learn_window = LearnInterface()
    # DataExtraction window
    dataExtraction_window = DataExtractionInterface()

    # setting all windows relationships
    config()

    main_window.show()
    sys.exit(app.exec_())
