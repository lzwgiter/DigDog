# coding=utf-8
import argparse


class DigDogLearnParser(object):

    def __init__(self):
        self.parser = argparse.ArgumentParser(prog='DigdogLearn',
                                              description='根据已有数据训练出模型并生成json模型说明')
        self.parser.add_argument('csv', type=str, help='要学习的CSV数据路径')
        self.parser.add_argument('-v', '--verbose', action='store_true', help='启用详细输出')
        self.parser.add_argument("--classifier",
                                 choices=["DecisionTree", "RandomForest", "ExtraTrees", "AdaBoost", "GradientBoosting",
                                          "SVM", "MLP", "KNN"],
                                 default="ExtraTrees", help="用于学习的树型学习方法")
        self.parser.add_argument('--feature_selection', action='store_true', help='在输出的json模型说明中增加启用的features项目')
        self.parser.add_argument('--undersampling', action='store_true',
                                 help='随机采样良性样本以防止过多良性样本干扰学习')
        self.parser.add_argument('--scaling', action='store_true',
                                 help='预先处理学习前的数据')
        self.parser.add_argument('model_name', type=str, help='模型名称')
        self.parser.add_argument('model_outpath', type=str, help='模型输出地址')

    def parse(self, args):
        return vars(self.parser.parse_args(args))


class DigDogDetectParser(object):

    def __init__(self):
        self.parser = argparse.ArgumentParser(prog='DigdogReport',
                                              description='DigdogScan可用于检测是否存在HBCIA攻击痕迹')
        self.parser.add_argument('dump', type=str, help='内存转储地址')
        self.parser.add_argument('--custom_model', type=str, help='模型说明路径')
        self.parser.add_argument('--prefilter', type=str, help='要过滤的vad节点的csv列表', default=None)
        self.parser.add_argument('-v', '--verbose', action='store_true', help='启用详细输出')
        self.parser.add_argument('--with_malfind', action='store_true', help='启用malfind辅助扫描')
        self.parser.add_argument('--with_hollowfind', action='store_true', help='启用hollowfind辅助扫描')
        self.parser.add_argument('-vp', '--profile', type=str, default='WinXPSP2x86',
                                 help='分析内存所使用的profile(默认为WinXPSP2x86)')

    def parse(self, args):
        return vars(self.parser.parse_args(args))


class DigDogDataExtractionParser(object):

    def __init__(self):
        self.parser = argparse.ArgumentParser(prog='DigdogDataExtraction',
                                              description='DigdogDataExtraction生成内存转储文件并提取其特征值')
        self.parser.add_argument("os", type=str, help="要储存数据的数据库名称")
        self.parser.add_argument('-v', '--verbose', action='store_true')
        self.parser.add_argument('-l', '--logfile')

        subparsers = self.parser.add_subparsers(dest='function')

        parserFeedSamples = subparsers.add_parser('feedSamples', help="插入可执行样本到数据库")
        parserFeedSamples.add_argument("path", help="样本的路径")
        parserFeedSamples.add_argument("classification", choices=["malicious", "benign"])
        parserFeedSamples.add_argument("--overwrite", action="store_true",
                                       help="覆写数据库中已存在的信息")

        parserGenerateDumps = subparsers.add_parser('generateDumps',
                                                    help="执行每一个样本并生成对应转储文件")
        parserGenerateDumps.add_argument("path", help="存放转储压缩文件的位置")
        parserGenerateDumps.add_argument("--overwrite", action="store_true",
                                         help="覆写数据库中已存在的信息")

        parserCreateGroundTruth = subparsers.add_parser('createGroundTruth',
                                                        help="用yara文件判断哪一个进程被感染,并生成对应GroundTruth")
        parserCreateGroundTruth.add_argument("path", nargs="+",
                                             help="yara文件的路径,可以传多个参数，Digdog会自动搜索与恶意样本名字相同的yara文件,"
                                                  "如：zeus.exe --- zeus.yara")

        parserAddGroundTruth = subparsers.add_parser('addGroundTruth',
                                                     help="将")
        parserAddGroundTruth.add_argument("path", help="GroundTruth路径")

        parserExtractFeatures = subparsers.add_parser('extractFeatures',
                                                      help="提取内存转储文件特征值并存入数据库")
        parserExtractFeatures.add_argument("--overwrite", action="store_true",
                                           help="覆写数据库中已存在的信息")

        parserExportRawData = subparsers.add_parser('exportRawData',
                                                    help="将特征值结果导出到csv文件")
        parserExportRawData.add_argument("path", help="csv文件路径")

    def parse(self, args):
        return self.parser.parse_args(args)
