# -*- encoding: utf-8 -*-
"""
@File    : thread_delay_detect.py.py
@Time    : 2020/3/25 下午11:03
@Author  : QYDD
@Description : check if there are malicious threads in process by its DCT(Delay Create Time)
"""


def scan(Scanner):
    """
    main scan procedure
    :param Scanner: QuincyScan class
    :return: (dict) vads result
    """
    output = {}

    for process in Scanner.processes:
        output[str(process.Id)] = scan_thread(process)
    return output


def scan_thread(process):
    """
    report malicious only if the threads' CreateTime is delayed for more than 1s
    :param process: process to scan
    :return: (dict) process detection result
    """
    result = {}
    for thread in process.Threads:
        create_time_t = thread.CreateTime
        if 1 <= create_time_t - process.CreateTime < 120:
            # mark process as malicious process once found thread has delay
            mark_process_malicious(process, result)
            return result

    # mark process as benign process
    mark_process_benign(process, result)
    return result


def mark_process_malicious(process, result):
    """
    mark all vads in malicious process as malicious vad
    :param process: process to mark as benign, this will mark its all vads as malicious
    :param result: (dict) the result of all vads
    :return:
    """
    """ mark all vads in malicious process as malicious vad """
    for vad in process.VADs:
        name = hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]
        result[name] = 1


def mark_process_benign(process, result):
    """
    mark all vads in benign process as benign
    :param process: process to mark as benign, this will mark its all vads as benign
    :param result: (dict) the result of all vads
    :return:
    """
    """ mark all vads in benign process as benign """
    for vad in process.VADs:
        name = hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]
        result[name] = 0
