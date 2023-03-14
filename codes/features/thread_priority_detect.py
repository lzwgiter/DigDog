# -*- encoding: utf-8 -*-
"""
@File    : thread_priority_detect.py
@Time    : 2020/3/28 下午6:18
@Author  : QYDD
@Description : check if there are malicious threads in process by judging its priority
"""


def scan(Scanner):
    """
    main scan procedure
    :param Scanner: QuincyScan class
    :return: (dict) vads result
    """
    output = {}
    for process in Scanner.processes:
        is_maicious_process = 0
        if not process.Threads:
            result = mark_process_benign(process)
            output[str(process.Id)] = result
            continue
        for thread in process.Threads:
            if not is_maicious_process:
                find_malicious = judge_thread(thread)
                if find_malicious:
                    is_maicious_process = 1
                if thread == process.Threads[-1]:
                    # all threads are benign threads --- benign process
                    result = mark_process_benign(process)
                    output[str(process.Id)] = result
            else:  # is malicious process
                result = mark_process_malicious(process)
                output[str(process.Id)] = result
                break

    return output


def judge_thread(thread):
    """
    find if current threads' priority is higher than owner process
    :param thread: Thread to check
    :param process: Owner process
    :return 1 if is malicious, otherwise, 0
    """
    # 系统只能提升优先级在（1~15 ，不会高于15）, 此范围内的变化属于微调
    if 0 < thread.BasePriority <= 15:
        if 0 < thread.Priority <= 15:
            return 0
        else:
            return 1
    else:
        # 但是系统不会动态提高范围（16~31）的线程。
        if thread.Priority > thread.BasePriority:
            return 1
        else:
            return 0


def mark_process_malicious(process):
    """
    mark all vads in malicious process as malicious vad
    :param process: process to mark as malicious, this will mark its all vads as malicious
    :return: (dict) the result of all vads
    """
    result = {}
    for vad in process.VADs:
        name = hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]
        result[name] = 1
    return result


def mark_process_benign(process):
    """
    mark all vads in benign process as benign
    :param process: process to mark as benign, this will mark its all vads as benign
    :return: (dict) the result of all vads
    """
    result = {}
    for vad in process.VADs:
        name = hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]
        result[name] = 0
    return result
