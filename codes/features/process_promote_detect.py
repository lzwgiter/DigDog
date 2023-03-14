# -*- encoding: utf-8 -*-
"""
@File    : process_promote_detect.py
@Time    : 2020/3/31 下午10:37
@Author  : QYDD
@Description : detect priority promotion in processes
"""
import yara
import os


def scan(Scanner):
    """
    main scan procedure
    :param Scanner:
    :return: output
    """
    p = os.path.join(os.path.split(os.path.realpath(__file__))[0], 'yara/escalate_priv.yar')
    rules = yara.compile(filepath=p)
    output = {}
    for process in Scanner.processes:
        output[str(process.Id)] = scan_vads(process, rules)
    return output


def scan_vads(process, rules):
    """
    using yara rules to match malicious processs
    :param process: process to scan
    :param rules: yara rules
    :return: process result
    """
    for vad in process.VADs:
        data = vad.read()
        matches = rules.match(data=data)
        if len(matches) > 0:
            result = mark_process_malicious(process)
            return result
    # benign process
    result = mark_process_benign(process)
    return result


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
