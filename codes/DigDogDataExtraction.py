# coding=utf-8
import collections
import datetime
import logging
import os
import platform
import signal
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

import tempfile
import time
from json import load

import DigDogConfig
import dump_generation.VirtualBox
from DigDogConfig import profiles, characteristics, BIN_PATH
from DigDogScan import DigDogScan
from dump_generation.MemoryDumpGenerator import MemoryDumpGenerator
from util import DigDogDatabase
from util import DigDogUtils
from util.DigDogParser import DigDogDataExtractionParser
from volatility_interface.VolatilityInterface import Process

job = None


class FeatureExtractor(object):

    def __init__(self, os_, database_, overwrite=False):
        self.profile = profiles[os_]
        self.characteristics = characteristics
        self._db = database_
        assert isinstance(self._db, DigDogDatabase.Database)
        self.overwrite = overwrite

    def extract(self):
        logging.info("[开始特征提取]")
        logging.info("根据你的配置，本次提取将使用%d个特征向量." % len(self.characteristics))
        dumps = self._db.iterDumps()
        i = 0
        for dump in dumps:
            i += 1
            logging.info("当前内存文件编号：%i" % i)
            logging.info("groundtruth信息：%r" % (dict((key, dump[key]) for key in dump if key != "results")))
            try:
                if 'results' not in dump:
                    todo = self.characteristics
                else:
                    todo = [c for c in self.characteristics
                            if not all(
                            c.__name__.split('.')[-1] in process['results'] for process in dump['results'].values())]
                if not todo:
                    logging.info("所有特征已提取完成，跳过")
                    continue
                self.extract_from_dump(dump, todo)
            except IOError as e:
                if e.errno != 2:
                    raise
                logging.warning(
                    '找不到内存文件%r (%s). 跳过%r' % (dump['path'], e, dump['name']))
            except Exception as e:
                logging.warning('Could not process dump %r (%s)' % (dump['path'], e))
                raise
        logging.info("[特征提取结束]")

    def extract_from_dump(self, dump, characteristics):
        entries = dict()
        if 'results' in dump:
            entries = dump['results'].copy()
        path = dump['path']
        if os.path.exists(path):
            logging.disable(logging.CRITICAL)
            scanner = DigDogScan(path, profile=self.profile)
            logging.disable(logging.NOTSET)
            scanner.extract_features(characteristics)
            scanner.cleanup()
            self.__add_scanner_results_to_db(entries, scanner)
            self._db.addDumpResults(dump, entries)
        else:
            logging.error("%s:file not exist!skip..." % path)

    def __add_scanner_results_to_db(self, entries, scanner):
        for process in scanner.processes:
            assert isinstance(process, Process)
            pid = str(process.Id)
            if pid not in entries:
                entries[pid] = {
                    'name': process.Name,
                    'results': self.__get_results(scanner, str(process.Id))
                }
            else:
                entries[pid]['results'].update(self.__get_results(scanner, str(process.Id)))

    @staticmethod
    def __get_results(scanner, pid):
        results = {}
        for characteristic in scanner.feature_results:
            if str(pid) in characteristic[1]:
                results[characteristic[0]] = characteristic[1][str(pid)]
            else:
                logging.warning("No result from %r for pid %r", characteristic[0], pid)
                results[characteristic[0]] = []
        return results


class QuincyDataExtraction(object):

    def __init__(self, os_, verbose=False):
        self.os = os_
        self.verbose = verbose
        self._db = DigDogDatabase.Database(DigDogConfig.hostname, DigDogConfig.port, db_name=os_)
        self.paused = False
        DigDogConfig.vm['name'] = DigDogConfig.vm['machines'][self.os]

    def signal_handler_pause(self, signum, frame):
        logging.warning("Got signal SIGUSR1. Pausing...")
        self.paused = True

    def signal_handler_unpause(self, signum, frame):
        logging.warning("Got signal SIGUSR2. Unpausing...")
        self.paused = False

    def feedSamples(self, path, classification, overwrite):
        logging.info('[%s] 样本正在插入中... [路径:%s]' % (classification, path))
        if os.path.isfile(path):
            success = self._db.addSample(path, classification, overwrite)
            if success:
                logging.info("样本插入成功！ [路径:%s]", path)
            else:
                logging.info("样本添加无效")
            return

        samples = os.listdir(path)
        if not samples:
            logging.warning('%s 不存在' % path)
            return

        num_samples_added = 0
        for sampleName in samples:
            sample_path = os.path.join(path, sampleName)
            success = self._db.addSample(sample_path, classification, overwrite)
            if success:
                num_samples_added += 1

        if num_samples_added:
            logging.info("成功插入样本数： %s", num_samples_added)
        else:
            logging.info("样本添加无效")

    def generate_dumps(self, path, overwrite):
        logging.info('导出内存至%s ..' % path)
        for classification in ['malicious', 'benign']:
            samples = list(self._db.getSamples(classification))
            generator = MemoryDumpGenerator(DigDogConfig.vm, silent=(not self.verbose), no_autorun=True)
            if classification == 'benign':  # reduce execution time for beingn samples
                generator.settings['time'] /= 2
            j, n = (0, len(samples))
            logging.info('共计%d个%s样本' % (n, classification))
            for i, sample in enumerate(samples):
                if not overwrite and self._db.dumpExists(sample['_id']):
                    logging.info('(%d/%d) 跳过 "%s"' % (i + 1, n, sample['name']))
                    continue
                logging.info('(%d/%d) 正在生成"%s"的内存文件' % (i + 1, n, sample['name']))
                outpath = self.__get_outpath(path, sample)
                entry = self.__get_entry(outpath, sample)
                try:
                    self.__generate_dump(generator, outpath, sample)
                    time.sleep(1)  # unlockMachine doesn't unlock immediately
                    self._db.addDumpInfo(entry, overwrite)
                    j += 1
                except dump_generation.VirtualBox.VBoxException as e:
                    logging.error("Error while dumping %r: ", sample["name"], exc_info=e)
                except Exception as e:
                    logging.error("Unexpected error while dumping %r: ", sample["name"], exc_info=e)
                self.__check_if_paused()

    def __check_if_paused(self):
        if self.paused:
            logging.warning("Execution paused. ")
            print "输入Enter以跳过"
            # Clearing stdin to prevent previous input to cause continuation
            DigDogUtils.clear_stdin()
            self.__pause()

    def __pause(self):
        while self.paused:
            if DigDogUtils.enter_pressed:
                self.paused = False
            time.sleep(1)
        logging.warning("Continuing")

    def __generate_dump(self, generator, outpath, sample):
        temp_dir = "/dev/shm"
        if "Darwin" in platform.platform():
            temp_dir = "/tmp"
        # FIXED : add with a .exe suffix
        with tempfile.NamedTemporaryFile(dir=temp_dir, prefix=sample["name"] + "_", suffix=".exe",
                                         mode='w+b') as sample_file:
            raw = self._db.getSampleBinary(sample['raw'])
            sample_file.write(raw)
            sample_file.flush()
            generator.generate(outpath, sample_file.name)

    @staticmethod
    def __get_entry(outpath, sample):
        entry = {
            '_id': sample['_id'],
            'name': sample['name'],
            'path': outpath,
            'infected': list()
        }
        return entry

    @staticmethod
    def __get_outpath(path, sample):
        out_dir = os.path.join(path, sample['classification'])
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)
        out_path = os.path.join(out_dir, sample['name'] + '.gz')
        return out_path

    def add_ground_truth(self, path):
        logging.info('正在将%s加入数据库' % path)
        with open(path, 'r') as f:
            data = load(f)
        for dump in self._db.iterDumps():
            if dump['name'] in data:
                self._db.addGroundTruthToDump(dump, data[dump['name']])

    def __isMaliciousDump(self, p):
        return "malicious" in p

    def create_ground_truth(self, paths):
        # search all malicious dumps in db
        dumps = [dump['path'] for dump in self._db.iterDumps() if self.__isMaliciousDump(dump['path'])]
        groundTruthFile = "ground_truth_%s_%s.json" % (self.os, datetime.datetime.now().strftime('%F_%T'))
        logging.debug("util/DigDogCreateGroundTruth.py --os %s --yara-signature-path %s --dumps %s > %s" % (
            self.os, " ".join(paths), " ".join(dumps), groundTruthFile))
        os.system("%s/util/DigDogCreateGroundTruth.py --os %s --yara-signature-path %s --dumps %s > %s" %
                  (BIN_PATH, self.os, " ".join(paths), " ".join(dumps), groundTruthFile))

    def extract_features(self, overwrite):
        logging.info('正在提取模块信息...')
        fc = FeatureExtractor(self.os, self._db, overwrite)
        fc.extract()

    @staticmethod
    def __get_vad_results(exportable_features, results):
        vadDict = collections.defaultdict(list)
        for exportable_feature in exportable_features:
            if exportable_feature in results:
                # ToDo: FIXME!
                if type(results[exportable_feature]) == float:
                    print "SOMETHING BROKEN"
                    print exportable_feature, results[exportable_feature]
                    continue
                for k, v in results[exportable_feature].iteritems():
                    vadDict[k] += [v]
            else:
                for k in vadDict.iterkeys():
                    vadDict[k] += ["NAN"]
        return vadDict

    @staticmethod
    def _is_infected(pid, vad, infected_vads):
        for infected_vad in infected_vads:
            if int(pid) == int(infected_vad[0]):
                vadName = hex(int(infected_vad[1])) + "_" + hex(int(infected_vad[2]))
                if vadName in vad:
                    return True
        return False

    def export_raw_data(self, path):
        exportable_features = []
        for c in DigDogConfig.characteristics:
            characteristic_name = c.__name__.split('.')[-1]
            exportable_features.append(characteristic_name)
        exportable_features = sorted(exportable_features)
        logging.info("%i个特征向量将被导出: %s" % (len(exportable_features), exportable_features))

        out_file = open(path, "w")
        header = "vad"
        for feature in exportable_features:
            header += "," + feature
        header += ",ground_truth\n"
        out_file.write(header)

        for dump in self._db.iterDumps():
            logging.info("导出{0}中...".format(dump["name"]))
            name = dump["name"]
            infected_vads = []
            if "infected" in dump:
                infected_vads = dump["infected"]
            if "results" in dump:
                for res in dump["results"]:
                    # current process
                    proc_prefix = name + "_" + res

                    vad_results = self.__get_vad_results(exportable_features, dump["results"][res]["results"])
                    for k in vad_results.iterkeys():
                        row = proc_prefix + "_" + k
                        for feat in vad_results[k]:
                            row += "," + str(feat)
                        if self._is_infected(res, k, infected_vads):
                            row += ",0"
                        else:
                            row += ",1"
                        row += "\n"
                        if not "None" in row:
                            out_file.write(row)
                        else:
                            logging.error("Invalid feature values for %s" % proc_prefix)
            else:
                logging.info("\t%r无特征结果", dump["name"])
        out_file.close()

        logging.info("导出文件路径: %s" % path)


def watchdog():
    try:
        start_time = datetime.datetime.now()
        main()
        runtime = str(datetime.datetime.now() - start_time).split('.')[0]
        msg = "%r结束。 用时: %s" % (job, runtime)
    except:
        try:
            from traceback import format_exc
            msg = '[CRASH] python quincy_data_extraction.py %s' % (' '.join(sys.argv[1:]))
            msg += '\n' + format_exc()
            logging.info(msg)
        finally:
            raise


def init(args):
    DigDogUtils.set_up_logging(args.verbose)

    if args.logfile:
        file_handler = logging.FileHandler(args.logfile)
        file_handler.setFormatter(logging.Formatter("%(asctime)s:%(levelname)-5s:%(message)s"))
        logger = logging.getLogger('')
        logger.addHandler(file_handler)
        logger.setLevel(logging.DEBUG)
        logging.debug("Command: %r", ' '.join(sys.argv))

    global job
    job = args.function


def main():
    parser = DigDogDataExtractionParser()
    args = parser.parse(sys.argv[1:])
    init(args)

    quincy_extractor = QuincyDataExtraction(args.os.lower(), args.verbose)
    signal.signal(signal.SIGUSR1, quincy_extractor.signal_handler_pause)
    signal.signal(signal.SIGUSR2, quincy_extractor.signal_handler_unpause)
    if args.function == 'feedSamples':
        quincy_extractor.feedSamples(args.path, args.classification, args.overwrite)
    elif args.function == 'generateDumps':
        quincy_extractor.generate_dumps(args.path, args.overwrite)
    elif args.function == 'createGroundTruth':
        quincy_extractor.create_ground_truth(args.path)
    elif args.function == 'addGroundTruth':
        quincy_extractor.add_ground_truth(args.path)
    elif args.function == 'extractFeatures':
        quincy_extractor.extract_features(args.overwrite)
    elif args.function == 'exportRawData':
        quincy_extractor.export_raw_data(args.path)


if __name__ == '__main__':
    watchdog()
