# coding=utf-8
import os
import sys
import time
import logging
import pickle
import json
import pandas as pd
import hexdump
import hashlib
import zlib
import threading
import threadpool
from sklearn import preprocessing, __version__

import DigDogConfig
from volatility_interface.VolatilityInterface import VolatilityInterface
from util.DigDogParser import DigDogDetectParser

from util import DigDogUtils
from features import malfind
from features import hollowfind

lock = threading.Lock()


class FeaturesCountError(Exception):
    def __str__(self):
        return 'DigDogConfig[characteristics] count error!'


class ScanResult(object):

    def __init__(self, process_id, vad_start, vad_end, result, content):
        self.process_id = process_id
        self.vad_start = vad_start
        self.vad_end = vad_end
        self.result = result
        self.vad_content = content


class DigDogScan(object):

    def __init__(self, path, custom_model=None, profile='WinXPSP2x86', with_malfind=False, with_hollowfind=False,
                 report=0):
        self.profile = profile
        self.path = path
        self.withMalfind = with_malfind
        self.withHollowfind = with_hollowfind
        if custom_model is not None:
            self.model, self.model_selected_features = self.__load_model(custom_model)
        self.__init_extract_dump(path, profile)

        self.__init_volatility(profile, report=report)

        # malicious results
        self.malicious_results = []
        # all features' results
        self.feature_results = []

    def __init_volatility(self, profile, report=0):
        logging.critical("[Volatility框架启动中]")
        logging.disable(logging.ERROR)
        self.vi = VolatilityInterface(self.path, profile, report)
        logging.disable(logging.NOTSET)
        self.processes = self.vi.Processes
        self.threads = self.vi.Threads

    def __init_extract_dump(self, path, profile):
        logging.debug("Initializing the dump.")
        self.temp = DigDogUtils.tryExtractDump(path, profile)
        if self.temp:
            self.path = self.temp

    def __is_compressed(self, data):
        try:
            zlib.decompress(data)
            return True
        except:
            return False

    def __load_model(self, path_model_description):
        logging.debug("Loading model description %s" % path_model_description)
        model_description = json.load(open(path_model_description))

        model_path = path_model_description.replace(".json", ".model")
        logging.info("Classifier: %s" % model_description["classifier"]["classifier"])

        with open(model_path, "rb") as f:
            model_data = f.read()

        if self.__is_compressed(model_data):
            logging.info("模型解压中...")
            model = pickle.loads(model_data.decode("zlib"))
        else:
            model = pickle.loads(model_data)

        selected_features = []
        if 'feature_selection_results' in model_description:
            selected_features = model_description['feature_selection_results']['selected']
            logging.info("模型选择了以下特征向量: %s" % str(selected_features))

        if "scaling" in model_description:
            if model_description["scaling"]:
                logging.info("模型需要数据预处理....")
            self._scaling = model_description["scaling"]
        else:
            self._scaling = False

        return model, selected_features

    def scan(self):
        # get all valid features(malfind,hollowfind not included)
        characteristics_without_other_heuristics = self.__get_features()
        if characteristics_without_other_heuristics is None:
            raise FeaturesCountError()
        logging.debug("finish feature counting")

        # call each features' scan function to get the result
        self.extract_features(characteristics_without_other_heuristics)

        # traversal each vad in each process, and conclude by comparing model.predict with feature result
        logging.critical("[开始恶意进程检测]")
        self.__detect()
        # result example:[(ScanResult),(ScanResult), ...],ScanResult:(pid, vad_start, vad_end, result)
        # the result of class ScanResult is model prediction

    def __run_module(self, characteristic, name):
        start = time.clock()
        try:
            lock.acquire()
            results = characteristic.scan(self)
            lock.release()
        except Exception, e:
            lock.release()
            logging.warning('Module "%s" has failed (%s)' % (characteristic, e))
            raise

        logging.debug('Module %s completed scan in %.2f seconds' % (name, (time.clock() - start)))
        return results

    def __remove_unpacked_dump(self):
        if self.temp and os.path.exists(self.temp):
            logging.info("清理%s及其临时文件中..." % self.temp)
            try:
                os.remove(self.temp)
                # remove the tmp directorys
                os.rmdir(os.path.dirname(self.temp))
            except:
                logging.error("%s清理失败！" % self.temp)

    def __is_selected_feature(self, feature_name):
        # return true if feature_name is in the list of *model_description*
        for d in self.model_selected_features:
            if d == feature_name:
                return True
        return False

    def __get_features(self):
        valid_features = []
        # -2 means not including malfind, hollowfind
        if self.withMalfind and self.withHollowfind:
            logging.info("可用向量数量： %i" % (len(DigDogConfig.characteristics) - 2))
        elif self.withMalfind or self.withHollowfind:
            logging.info("可用向量数量： %i" % (len(DigDogConfig.characteristics) - 1))
        else:
            logging.info("可用向量数量： %i" % (len(DigDogConfig.characteristics)))
        for c in DigDogConfig.characteristics:
            feature_name = c.__name__.split('.')[-1]
            if feature_name != "malfind" and feature_name != "hollowfind" and self.__is_selected_feature(feature_name):
                # add to valid features
                valid_features.append(c)

        if len(valid_features) < len(self.model_selected_features):
            logging.error(
                "所需向量数(%d)小于模型所需向量数!请检查DigDogConfig" % len(
                    self.model_selected_features))
            return None
        logging.info("经过选择，使用%i个向量" % len(valid_features))
        return valid_features

    def extract_features(self, characteristics_):
        start = time.clock()
        task_pool = threadpool.ThreadPool(4)
        tasks = threadpool.makeRequests(self.__extract_feature, characteristics_)
        for task in tasks:
            task_pool.putRequest(task)
        task_pool.wait()

        logging.info('所有扫描结束，用时%.2f seconds' % (time.clock() - start))

    def __extract_feature(self, characteristic):
        feature_name = characteristic.__name__.split('.')[-1]
        logging.info("[%s] 运行中 : %s" % (threading.current_thread().name, feature_name))
        try:
            self.feature_results.append((feature_name, self.__run_module(characteristic, feature_name)))
        except Exception, e:
            logging.warning('不能加载模块： "%s" (%s)' % (feature_name, e))
            raise

    def __hash_vad(self, vad):
        hash_obj = hashlib.sha256(vad.read())
        return hash_obj.hexdigest()

    def __detect(self):
        malfind_results = None
        if self.withMalfind:
            logging.info("[malfind] 运行中...")
            malfind_results = malfind.scan(self)

        hollowfind_results = None
        if self.withHollowfind:
            logging.info("[hollowfind] 运行中...")
            hollowfind_results = hollowfind.scan(self)

        self.scan_results = []
        for process in self.processes:
            logging.debug("Current process: %i" % process.Id)
            if malfind_results is not None:
                malfind_results_for_process = malfind_results[str(process.Id)]
            else:
                malfind_results_for_process = None
            if hollowfind_results is not None:
                hollowfind_results_for_process = hollowfind_results[str(process.Id)]
            else:
                hollowfind_results_for_process = None

            for vad in process.VADs:
                vadResult = self.__detect_vad(malfind_results_for_process, hollowfind_results_for_process, process, vad)
                if vadResult.result == DigDogConfig.MALICIOUS:
                    # output result
                    self.malicious_results.append(vadResult)
            # end-of-vads-recursive
        # end-of-processes-recursive

    def __hexdump_vad_start(self, pid, vadStart):
        for process in self.processes:
            if process.Id == pid:
                data = process.read(vadStart, DigDogConfig.HEXDUMP_BYTES)
                hex_result = hexdump.hexdump(data, result='return')
                return hex_result

    def __detect_vad(self, malfind_results_for_process, hollowfind_results_for_process, process, vad):
        logging.debug('\t#%d "%s" VAD 0x%x with size 0x%x' % (process.Id, process.Name, vad.Start, vad.End - vad.Start))

        if malfind_results_for_process is not None:
            malfind_result_for_vad = malfind_results_for_process[hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]]
        else:
            malfind_result_for_vad = None

        if hollowfind_results_for_process is not None:
            hollowfind_result_for_vad = hollowfind_results_for_process[hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]]
        else:
            hollowfind_result_for_vad = None

        vad_results = self.__get_vad_results(process, vad)
        vad_data = pd.DataFrame.from_dict(vad_results)
        if self._scaling:
            vad_data = preprocessing.scale(vad_data)
        modelPrediction = self.model.predict(vad_data)

        if modelPrediction == DigDogConfig.MALICIOUS:
            vad_result = self.__log_malicious_vad(malfind_result_for_vad, malfind_results_for_process,
                                                  hollowfind_result_for_vad,
                                                  hollowfind_results_for_process, process, vad, vad_results)
        else:
            self.__log_benign_vad(malfind_result_for_vad, malfind_results_for_process, hollowfind_result_for_vad,
                                  hollowfind_results_for_process,
                                  process, vad)
            vad_result = None
        return ScanResult(process.Id, vad.Start, vad.End, modelPrediction, vad_result)

    def __get_vad_results(self, process, vad):
        vad_results = {}
        for feature in self.feature_results:
            if str(process.Id) in feature[1]:
                for vadRes in feature[1][str(process.Id)]:
                    name = hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]
                    if name in vadRes:
                        vad_results[feature[0]] = [feature[1][str(process.Id)][vadRes]]
        logging.debug("\t\t%s" % str(vad_results))
        return vad_results

    def __log_benign_vad(self, malfind_result_for_vad, malfind_results_for_process, hollowfind_result_for_vad,
                         hollowfind_results_for_process, process, vad):
        logging.debug('进程: %i, VAD 0x%x 为良性!' % (process.Id, vad.Start))
        if malfind_results_for_process is not None and malfind_result_for_vad == DigDogConfig.MALICIOUS:
            logging.warning(
                '与malfind冲突! [malfind]: %i, VAD 0x%x 为恶性!' % (process.Id, vad.Start))
        if hollowfind_results_for_process is not None and hollowfind_result_for_vad == DigDogConfig.MALICIOUS:
            logging.warning(
                '与hollowfind冲突! [hollowfind]: %i, VAD 0x%x 为恶性!' % (process.Id, vad.Start))

    def __log_malicious_vad(self, malfind_result_for_vad, malfind_results_for_process, hollowfind_result_for_vad,
                            hollowfind_results_for_process, process, vad, vad_results):
        logging.warning(
            '进程: %i - %s, VAD 0x%x 为恶性!' % (process.Id, process.Name, vad.Start))
        vad_result = self.__hexdump_vad_start(process.Id, vad.Start)
        if malfind_results_for_process is not None:
            if malfind_result_for_vad == DigDogConfig.MALICIOUS:
                logging.warning("malfind判断相同！[malfind]: %i, VAD 0x%x 为恶性!" % (process.Id, vad.Start))
            else:
                logging.warning("与malfind冲突! [malfind]: %i, VAD 0x%x 为良性!" % (
                    process.Id, vad.Start))
        if hollowfind_results_for_process is not None:
            if hollowfind_result_for_vad == DigDogConfig.MALICIOUS:
                logging.warning("hollow判断相同！[hollow]: %i, VAD 0x%x 为恶性!" %
                                (process.Id, vad.Start))
            else:
                logging.warning("与hollowfind冲突! [hollowfind]: %i, VAD 0x%x 为良性!"
                                % (process.Id, vad.Start))
        logging.debug("\t\t%s" % str(vad_results))
        return vad_result

    def cleanup(self):
        logging.info("清理后台中...")
        self.__remove_unpacked_dump()


def get_precomputed_model(profile):
    for m in DigDogConfig.PRECOMPUTED_MODELS.iterkeys():
        if m in profile.lower():
            return DigDogConfig.PRECOMPUTED_MODELS[m]

    logging.error("Could not find precomputed model for Volatility profile %s" % profile)
    raise Exception("No precomputed model available.")


def main(args=None):
    if args is None:
        args = sys.argv[1:]

    parser = DigDogDetectParser()
    arguments = parser.parse(args)
    DigDogUtils.set_up_logging(arguments['verbose'])

    sys.argv = list()

    if "custom_model" in arguments and arguments["custom_model"] is not None:
        model = arguments["custom_model"]
    else:
        model = get_precomputed_model(arguments["profile"])

    try:
        digdogScan = DigDogScan(path=arguments['dump'],
                                custom_model=model,
                                profile=arguments['profile'],
                                with_malfind=arguments["with_malfind"],
                                with_hollowfind=arguments["with_hollowfind"])
        # get the ScanResult
        digdogScan.scan()
        digdogScan.cleanup()
    except Exception as e:
        print e


if __name__ == "__main__":
    print('The scikit-learn version is {}.'.format(__version__))
    main()
