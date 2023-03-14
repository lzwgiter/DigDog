# -*- encoding: utf-8 -*-
"""
@File    : DigDogReport.py
@Time    : 2020/3/31 下午10:27
@Author  : QYDD
"""
import os
import re
import sys
import json
import logging
import pefile
import requests
import base64
import webbrowser as web
from datetime import datetime
from subprocess import check_call

from DigDogConfig import dot_file_path, png_path, template_path, volatility_path, mal_proc_path, public_path
from DigDogScan import DigDogScan
from DigDogConfig import VIRUSTOTAL_KEY, DGA_ARCHIVE_USER, DGA_ARCHIVE_PASS
from util import DigDogUtils
from util.DigDogParser import DigDogDetectParser

from volatility.obj import NoneObject

# Start Time
start_time = ""
# Report File Name
report_file = "%s.md" % datetime.now().strftime('%F_%T')


class DigDogReport:

    def __init__(self, digdogScan, scanResult):
        self.scanner = digdogScan
        self.malicious_result = self._sort(scanResult)
        self._procDump()
        self.dot_file_path = dot_file_path
        # png stored directory must equal to md name
        self.pstree_png_path = png_path + "/%s_" % self.scanner.path.split("/")[-1] + report_file.split(".")[
            0] + "/result.png"

        self.raw_info = digdogScan.vi.Info
        self.raw_reg = digdogScan.vi.Registry
        self.networks = digdogScan.vi.Networks
        self.procDict = digdogScan.vi.backup
        self.raw_cmd = digdogScan.vi.CmdLine

        # Report Content
        self.info = ""
        self.mal_net = {}
        self.mal_dll = {}
        self.mal_func_list = {}
        self.mal_vad = {}
        self.mal_cmd = {}

    @staticmethod
    def _sort(results):
        pid_list = {}
        for result in results:
            if result.process_id in pid_list:
                pid_list[result.process_id].append(result)
            else:
                pid_list[result.process_id] = [result]
        return pid_list

    def _procDump(self):
        if self.malicious_result.keys():
            store_path = mal_proc_path + "/%s_" % self.scanner.path.split("/")[-1] + report_file.split(".")[0]
            os.mkdir(store_path)
            for mal_pid in self.malicious_result.keys():
                logging.info("[正在导出恶意进程文件 格式：.exe")
                cmd = 'python ' + volatility_path + ' ' + \
                      '-f ' + self.scanner.path + ' ' + \
                      '--profile=' + self.scanner.profile + ' ' + \
                      'procdump -p %d' % mal_pid + ' ' + \
                      '--dump-dir=%s' % store_path
                os.system(cmd)

    def run(self):
        """
        生成DigDog报告
        :return:
        """
        # information
        self.info += "{0} : {1}\n".format("可能的操作系统版本", ", ".join(self.raw_info[0][1].split(",")[:3]))
        self.info += "{0} : {1}\n".format("DTB目录表基址", self.raw_info[5][1])
        self.info += "{0} : {1}\n".format("KDBG信息", self.raw_info[6][1])
        self.info += "{0} : {1}\n".format("处理器核数", self.raw_info[7][1])
        self.info += "{0} : {1}\n".format("Windows服务包版本", self.raw_info[8][1])
        self.info += "{0} : {1}\n".format("镜像日期和时间", self.raw_info[12][1])
        self.info += "{0} : {1}\n".format("镜像本地日期和时间", self.raw_info[13][1])

        # network
        self.mal_net["title"] = "{0:<8}{1:<24}{2:<20}{3:<20}{4:<24}{5:<10}\n".format("PID", "本地地址", "本地端口", "协议类型",
                                                                                     "远程地址", "远程端口")
        self.mal_net["render"] = "{0:<8}{1:<18}{2:<15}{3:<14}{4:<18}{5:<20}\n".format('-' * 7, '-' * 17, '-' * 14,
                                                                                      '-' * 13, '-' * 17, '-' * 10)
        self.mal_net["result"] = []
        record = []
        for item in self.networks:
            if item.pid in self.malicious_result.keys():
                if item.raddr == "*":
                    continue
                elif item.raddr in record:
                    continue
                else:
                    if not isinstance(item.raddr, NoneObject):
                        record.append(item.raddr)
                    content, api = self._get_network(item)
                    self.mal_net["result"].append((content, api))

        # dllist
        self.mal_dll["title"] = "{0:<8}{1:<30}{2:<20}{3:<20}{4:<30}\n".format("PID", "进程名", "加载次数", "文件大小", "Dll名称")
        self.mal_dll["render"] = "{0:<8}{1:<26}{2:<14}{3:<15}{4:<30}\n".format('-' * 7, '-' * 25, '-' * 13, '-' * 14,
                                                                               '-' * 30)
        for mali_pid in self.malicious_result.keys():
            tmp_result = []
            for each_dll in self.procDict[mali_pid].Modules:
                tmp_result.append(
                    "{0:<8}{1:<26}".format(mali_pid, self.procDict[mali_pid].Name) + self._get_dll(each_dll))
            self.mal_dll[mali_pid] = tmp_result

        # pstree
        # create temp directory and write dot head information
        self._construct_dot_file()
        for pid in self.malicious_result.keys():
            proc_path = []
            self._get_pstree(pid, self.procDict, proc_path)
            self._release_process(pid)
        with open(self.dot_file_path, 'a') as f:
            f.write('}')
        f.close()
        cmdline = ['dot', '-Tpng', self.dot_file_path, '-o', self.pstree_png_path]
        check_call(cmdline)

        # Malicious Cmdline records
        for each_record in self.raw_cmd:
            # pid == malicious_pid
            if each_record[1] in self.malicious_result.keys():
                # {pid : (name, cmdline)}
                self.mal_cmd[each_record[1]] = (self.procDict[int(each_record[1])].Name, each_record[2])

        # Malicious VAD Information
        for pid in self.malicious_result.keys():
            for each_result in self.malicious_result[pid]:
                if pid in self.mal_vad:
                    self.mal_vad[pid].append((each_result.vad_start, each_result.vad_content))
                else:
                    self.mal_vad[pid] = [(each_result.vad_start, each_result.vad_content)]

        # generate report
        self.generate_report()

    def generate_report(self):
        path = template_path
        with open(path, 'r') as fp:
            output = fp.read()
        # registry string
        self.raw_reg = "{0:<50}{1:<20}\n".format("注册表内容",
                                                 "注册表项名称") + '-' * 42 + " " + '-' * 20 + '\n' + self.raw_reg

        # dll string
        dll_item = ""
        dll_item += self.mal_dll["title"]  # Title
        dll_item += self.mal_dll["render"]  # render
        self.mal_dll.pop("title")
        self.mal_dll.pop("render")
        for pid in self.mal_dll.keys():
            for module_list in self.mal_dll[pid]:
                for module_result in module_list:
                    dll_item += module_result
            dll_item += "\n"

        # Suspicious Dll Import Functions
        func_item = ""
        mal_dump_path = mal_proc_path + "/%s_" % self.scanner.path.split("/")[-1] + report_file.split(".")[0]
        if os.path.exists(mal_dump_path):
            for each_exe in os.listdir(mal_dump_path):
                current_pid = each_exe.split(".")[1]
                func_item += "进程PID: {0} 进程名: {1}\n".format(current_pid, self.procDict[int(current_pid)].Name)
                path = mal_proc_path + "/%s_" % self.scanner.path.split("/")[-1] + \
                       report_file.split(".")[0] + "/" + each_exe
                func_item = self._pe_analysis(path, func_item)
        else:
            logging.error("process not found")

        # network string
        net_item = ""
        api_item = "{0:<48}{1:<36}{2:<10}\n".format("可疑IP域名查询", "创建时间",
                                                    "恶意软件家族") + '-' * 40 + ' ' + '-' * 30 + ' ' + '-' * 20 + '\n'
        net_item += self.mal_net["title"]  # Title
        net_item += self.mal_net["render"]  # render
        self.mal_net.pop("title")
        self.mal_net.pop("render")
        # record : (content"", api(family{url"":family""}, url{url:time}))
        for record in self.mal_net["result"]:
            if record[0]:
                net_item += record[0]
            # not 127.0.0.1
            if record[1] != "skip":
                api_result = record[1]
                familys = api_result[0]
                urls = api_result[1]
                for index in urls.keys():
                    api_item += "{0:<41}{1:<31}{2:<10}\n".format(str(index), str(urls[index]), familys[index])

        # Cmdline Information
        cmd_item = ""
        cmd_item += "{0:<8}{1:<30}{2:<30}\n".format("PID", "进程名", "命令行参数")
        cmd_item += "-" * 7 + ' ' + '-' * 25 + ' ' + '-' * 30 + '\n'
        for key in self.mal_cmd.keys():
            cmd_item += "{0:<8}{1:<30}{2:30}\n".format(key, self.mal_cmd[key][0], self.mal_cmd[key][1])

        # VAD Information
        vad_item = ""
        for pid in self.mal_vad.keys():
            for vad_entry in self.mal_vad[pid]:
                vad_item += "进程 %d - VAD节点地址 0x%x\n" % (pid, vad_entry[0])
                vad_item += vad_entry[1] + "\n\n"

        end_time = datetime.now().strftime('%F_%T')

        # fill all result into md file
        mal_pid_item = ", ".join('%s' % malPid for malPid in self.malicious_result.keys())
        if self.mal_net["result"]:
            net_conclusion = "存在"
        else:
            net_conclusion = "不存在"
        result = output % (
            start_time, self.scanner.path.split("/")[-1], start_time, self.scanner.path, end_time, self.info, cmd_item,
            dll_item, func_item, vad_item,
            self.raw_reg, net_item, api_item, self.scanner.path, mal_pid_item, mal_dump_path, net_conclusion)
        file_name = png_path + "/%s_" % self.scanner.path.split("/")[-1] + report_file

        with open(file_name, 'w') as fp:
            fp.write(result)
        self.bootstrap()

    @staticmethod
    def AddFoldTag(string):
        z = ""
        y = re.findall(".*?<br>.*?", string)
        if y != "":
            for i in range(10):
                z += "".join(y[i])
            string = string.replace(z,
                                    z + '<div><div class="fold_hider"><div class="close hider_title">点击显/隐内容</div></div><div class="fold">')
            k = "".join(re.findall(".*?<br>.*?", string))
            string = string.replace(k, k + "</div></div>")
            return string
        else:
            return string

    @staticmethod
    def reindex():
        address1 = 'friends="友情链接" about="关于我"'
        address2 = '<footer id="footer">'

        add = ['<div class="article-entry" itemprop="articleBody">\n',
               '<h2>DigDog产品介绍</h2><p>DigDog是一款基于神经网络和内存取证的恶意软件检测系统，可以在短时间内实现对目标机器内存文件的多角度多层次扫描，从而获取恶意软件的运行痕迹。</p>\n',
               '<p>扫描结果以网页的形式呈现给用户，用户可以点击主页的所有报告按键以查看所有恶意软件检测报告。正如产品说明视频中展示的那样，本产品分为开发者模式和用户模式。获取待检测的内存转储文件之后，分析人员可以直接进入用户模式，完成学习模型选择等相关配置后运行产品，并在本网站中查看检测结果。同时，本产品具有高度的可扩展性，分析人员可以进入开发者模式并添加样本，从而不断优化检测模型，以提高模型的检测效率。</p>\n',
               '<h2>产品运行说明及演示视频</h2>\n',
               '<iframe src="//player.bilibili.com/player.html?aid=925814091&bvid=BV1wT4y1g7GS&cid=195373804&page=1" scrolling="no" border="0" frameborder="no" framespacing="0" allowfullscreen="true" width="100%" height="720"> </iframe>\n',
               '</div>\n']
        x = 0
        y = 0

        index_path = public_path + "/index.html"
        with open(index_path, 'r') as fh:
            fh_list = fh.readlines()

        for i in range(len(fh_list)):
            fh_line = "".join(fh_list[i])
            if address1 in fh_line:
                x = i + 2
            elif address2 in fh_line:
                y = i
        re_fh_list = fh_list[:x] + add + fh_list[y:]

        with open(index_path, 'w') as fn:
            for i in re_fh_list:
                fn.write(i)

    def rehtml(self, path):
        with open(path, 'r') as ft:
            ft_list = ft.readlines()
        reline1 = '<h3 id="DLL信息">'
        reline2 = '<h3 id="恶意节点信息">'
        reline3 = '<h3 id="加载函数信息">'

        # read origin content and re it
        for i in range(len(ft_list)):
            ft_line = "".join(ft_list[i])
            if reline1 in ft_line:
                ft_linetemp = "".join(ft_list[i + 1])
                ft_list[i + 1] = self.AddFoldTag(ft_linetemp)
            elif reline2 in ft_line:
                ft_linetemp = "".join(ft_list[i + 1])
                ft_list[i + 1] = self.AddFoldTag(ft_linetemp)
            elif reline3 in ft_line:
                ft_linetemp = "".join(ft_list[i + 1])
                ft_list[i + 1] = self.AddFoldTag(ft_linetemp)

        # write result back
        with open(path, 'w') as fr:
            for i in ft_list:
                fr.write(i)

    def format_report(self, path):
        current_path = path
        for dir_path_1 in os.listdir(public_path):
            if dir_path_1.isdigit():
                current_path += "/%s" % dir_path_1
                for dir_path_2 in os.listdir(current_path):
                    current_path += "/%s" % dir_path_2
                    # day
                    for dir_path_3 in os.listdir(current_path):
                        current_path += "/%s" % dir_path_3
                        for each_report in os.listdir(current_path):
                            self.rehtml("%s/%s/index.html" % (current_path, each_report))
                        current_path = "/".join(current_path.split("/")[:-1])
                    current_path = "/".join(current_path.split("/")[:-1])
                current_path = "/".join(current_path.split("/")[:-1])

    def bootstrap(self):
        curr_path = os.getcwd()
        path = curr_path[:-10] + "View"
        os.chdir(path)
        cmd1 = "hexo g"
        os.system(cmd1)
        self.reindex()
        cname_file = public_path + "/CNAME"
        with open(cname_file, 'w') as fp:
            fp.write("digdog-report.cn")
        self.format_report(public_path)
        cmd2 = "hexo d"
        os.system(cmd2)
        logging.info("[报告生成成功], 跳转中...")
        web.open("https://digdog-report.github.io/archives/")

    @staticmethod
    def _pe_analysis(path, output):
        pe = pefile.PE(path)
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for module in pe.DIRECTORY_ENTRY_IMPORT:
                output += ' ' * 4 + "[加载DLL名称：{0}]\n".format(module.dll)
                for func in module.imports:
                    if func.name:
                        output += ' ' * 8 + '|' + ' - ' + func.name + '\n'

        return output

    def _get_network(self, network):
        if isinstance(network.laddr, NoneObject):
            network.laddr = "Unknown"
        if isinstance(network.raddr, NoneObject):
            network.raddr = "Unknown"
        if network.laddr == "Unknown" and network.raddr == "Unknown":
            # ignored
            return "", "skip"

        content = "{0:^8}{1:^18}{2:^15}{3:^14}{4:^18}{5:^20}\n".format(network.pid, network.laddr, network.lport,
                                                                       network.protocol, network.raddr, network.rport)
        if network.raddr == "127.0.0.1":
            # no api check
            return content, "skip"
        elif network.raddr == "Unknown":
            # no api check
            return content, "skip"
        else:
            # virustotal check
            urls = self._virus_total_check(str(network.raddr))
            family = {}
            if urls:
                for each_url in urls.keys():
                    family[each_url] = self._DGA_family(str(each_url))
            return content, (family, urls)

    @staticmethod
    def _DGA_family(domain):
        ip = "https://dgarchive.caad.fkie.fraunhofer.de/r/" + domain
        family = ""
        tries = 0
        logging.info("[DGA 域名查询中]")
        logging.disable(logging.INFO)
        while tries < 3:
            try:
                result = json.loads(
                    requests.get(ip, auth=(base64.b64decode(DGA_ARCHIVE_USER), DGA_ARCHIVE_PASS), timeout=5).text)
                for each in result['hits']:
                    family += each['family'] + "; "
                logging.disable(logging.NOTSET)
                if family and family != 'None':
                    return family
                else:
                    return "无结果"
            except requests.exceptions.RequestException:
                tries += 1
                logging.warning("[DGArchive - 网络不稳定 - 重试中]")

    def _construct_dot_file(self):
        # make directory to store the png
        os.mkdir("/".join(self.pstree_png_path.split("/")[:-1]))
        with open(self.dot_file_path, 'w') as f:
            f.write('digraph output {\n' + '  node[shape = Mrecord];\n' + '  #rankdir=LR;\n')
        f.close()

    def _release_process(self, pid):
        with open(dot_file_path, 'a') as f:
            for item in self.procDict.keys():
                if self.procDict[item].Parent == pid:
                    release_process = self.procDict[item]
                    node_information = '  %s [label=\"{Name:%s|Pid:%s|PPid:%s|Thds:%s|Mod:%s|CreateTime:%s}\"];\n' % \
                                       (release_process.Id, release_process.Name, release_process.Id,
                                        release_process.Parent, len(release_process.Threads),
                                        len(release_process.Modules), release_process.CreateTime)
                    link_information = '  %s -> %s[color=red];\n' % (release_process.Parent, release_process.Id)
                    f.write(node_information)
                    f.write(link_information)
                else:
                    continue
        f.close()

    @staticmethod
    def _get_dll(module):
        content = "{0:<14}{1:<15}{2:<30}\n".format(module.LoadCount, module.Size, module.FullDllName)
        return content

    def _get_pstree(self, mali_pid, proc_dict, proc_path):
        if mali_pid in proc_dict:
            # Store the process object
            proc_path.append(proc_dict[mali_pid])
            if proc_dict[mali_pid].Parent in proc_dict:
                mali_ppid = proc_dict[mali_pid].Parent
                self._get_pstree(mali_ppid, proc_dict, proc_path=proc_path)
            else:
                self._log_pstree(proc_path)

    def _log_pstree(self, path):
        count = 0
        f = open(self.dot_file_path, 'a')
        while path:
            path.reverse()
            process = path.pop()
            if count == 0:
                # Write the information of malicious_process
                process_information = '  %s [fontcolor=red,color=red,label=\"{Name:%s|Pid:%s|PPid:%s|Thds:%s|Mod:%s|CreateTime:%s}\"];\n' % \
                                      (process.Id, process.Name, process.Id, process.Parent, len(process.Threads),
                                       len(process.Modules), process.CreateTime)
                if process.Parent in self.procDict.keys():
                    link_information = '  %s -> %s[color=red];\n' % (process.Parent, process.Id)
                else:
                    link_information = ''
                count = 1
            elif count == 1:
                process_information = '  %s [label=\"{Name:%s|Pid:%s|PPid:%s|Thds:%s|Mod:%s|CreateTime:%s}\"];\n' % \
                                      (process.Id, process.Name, process.Id, process.Parent, len(process.Threads),
                                       len(process.Modules), process.CreateTime)
                if process.Parent in self.procDict.keys():
                    link_information = '  %s -> %s[color=red];\n' % (process.Parent, process.Id)
                else:
                    link_information = ''
            f.write(process_information)
            f.write(link_information)
        f.close()

    @staticmethod
    def _virus_total_check(ip):
        url = "https://www.virustotal.com/api/v3/ip_addresses/" + ip + "/resolutions"
        querystring = {"limit": "10"}
        headers = {'x-apikey': VIRUSTOTAL_KEY}

        tries = 0
        logging.info("[VirusTotal DNS反查询中]")
        logging.disable(logging.INFO)
        while tries < 3:
            try:
                response = requests.request("GET", url, headers=headers, params=querystring, timeout=5)
                result = json.loads(response.text)
                raw_data = result["data"]
                output = {}
                for each_attribute in raw_data:
                    if each_attribute["attributes"]["host_name"] not in output:
                        output[each_attribute["attributes"]["host_name"]] = str(
                            datetime.fromtimestamp(each_attribute["attributes"]["date"]))
                logging.disable(logging.NOTSET)
                return output
            except requests.exceptions.RequestException:
                tries += 1
                logging.warning("[VirusTotal - 网络不稳定 - 重试中]")


def main(args=None):
    if args is None:
        args = sys.argv[1:]
    parser = DigDogDetectParser()
    arguments = parser.parse(args)
    DigDogUtils.set_up_logging(arguments['verbose'])

    model = arguments["custom_model"]
    try:
        digdogScan = DigDogScan(path=arguments['dump'],
                                custom_model=model,
                                profile=arguments['profile'],
                                with_malfind=arguments["with_malfind"],
                                with_hollowfind=arguments["with_hollowfind"],
                                report=1)
        # get the ScanResult
        digdogScan.scan()
        if not digdogScan.malicious_results:
            print "该样本未检测出恶意进程信息"
            exit(0)

        # quincyResults' structure : [(ScanResult),(ScanResult), ...]
        # ScanResult:(pid, vad_start, vad_end, result)
        digdogScanResult = digdogScan.malicious_results
        digdogReport = DigDogReport(digdogScan, digdogScanResult)
        digdogReport.run()

    except Exception as e:
        print e


if __name__ == '__main__':
    start_time = datetime.now().strftime('%F_%T')
    main()
