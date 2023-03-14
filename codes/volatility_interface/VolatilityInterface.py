# coding=utf-8
import logging

import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace
import volatility.utils as utils
import volatility.plugins.vadinfo as vadinfo
import volatility.plugins.malware.psxview as psxview
import volatility.plugins.malware.threads as threads
import volatility.plugins.netscan as netscan
import volatility.plugins.imageinfo as imageinfo
import volatility.plugins.registry.registryapi as registryapi
import volatility.plugins.cmdline as cmdline
from volatility.plugins import iehistory
from volatility.win32.tasks import pslist

logging.getLogger('volatility.utils').setLevel(logging.ERROR)
logging.getLogger('volatility.obj').setLevel(logging.ERROR)
logging.getLogger('volatility.win32.rawreg').setLevel(logging.ERROR)


class Thread:
    """ Class representing a thread in a dump. """

    def __init__(self, thread, memory):
        self.CreateTime = thread.CreateTime
        self.Offset = thread.obj_offset
        self.Tid = thread.Cid.UniqueThread
        self.Pid = thread.Cid.UniqueProcess
        self.State = thread.Tcb.State
        self.Memory = memory
        self.Priority = thread.Tcb.Priority
        self.BasePriority = thread.Tcb.BasePriority
        self.Start = thread.Win32StartAddress
        self.Register = thread.Tcb.TrapFrame.dereference_as("_KTRAP_FRAME")

    def __str__(self):
        return "Thread @ %s Tid: %d Pid: %d Start: %s (%s)" % (self.Offset,
                                                               self.Tid, self.Pid, self.Start, self.Register.Eip)


class Network:
    """ Class representing a network activity in a dump """

    def __init__(self, netobj, protocol, laddr, lport, raddr, rport):
        self.pid = int(netobj.Owner.UniqueProcessId)
        self.protocol = protocol
        self.laddr = laddr
        self.lport = lport
        self.raddr = raddr
        self.rport = rport


class VAD:
    """ Class representing a single VAD in a dump. """

    def __init__(self, vad, physicalMemory, virtualMemory):
        self.Offset = vad.obj_offset
        self.Start = vad.Start
        self.End = vad.End
        self.Tag = vad.Tag
        self.Flags = set()
        self.VadFlags = vad.VadFlags
        try:
            self.ControlFlags = vad.ControlArea.u.Flags
        except AttributeError:
            self.ControlFlags = None
        self.PhysicalMemory = physicalMemory
        self.VirtualMemory = virtualMemory
        if hasattr(vad, 'u'):
            infostring = vadinfo.PROTECT_FLAGS[vad.u.VadFlags.Protection.v()]
        else:
            infostring = ''
        try:
            self.File = str(vad.FileObject.FileName)
        except AttributeError:
            self.File = None
        if "EXECUTE" in infostring:
            self.Flags.update({"Execute", "Read"})
        if "WRITE" in infostring:
            self.Flags.update({"Write", "Read"})
        if "READ" in infostring:
            self.Flags.update({"Read"})
        if "NOACCESS" in infostring:
            self.Flags.update({"NoAccess"})

    def contains(self, address):
        """ Returns true if the vad contains the given address. """
        return self.Start <= address <= self.End

    def __str__(self):
        return "VAD @ %s Start: %s End: %s %s %s" % (hex(self.Offset),
                                                     hex(self.Start), hex(self.End), self.Flags, self.File)

    def read(self, offset=0, length=None):
        """ A method which reads the memory of a vad at the given offset.

            Keyword arguments:
            offset -- offset inside the VAD to read from
            length -- length of the test_data read
        """
        if not length:
            length = self.End - self.Start
            if length < 10 ** 9:  # FIXED: sometimes with unusual chunk size
                return self.VirtualMemory.zread(self.Start + offset, length)
            else:
                return ''


class Process:
    """ Class representing a logical process in a dump. """

    def __init__(self, eprocess, memory):
        self.Name = str(eprocess.SeAuditProcessCreationInfo.ImageFileName.Name).split("\\")[-1]
        self.Id = int(eprocess.UniqueProcessId)
        self.Parent = int(eprocess.InheritedFromUniqueProcessId)
        self.CreateTime = eprocess.CreateTime
        self.VirtualMemory = eprocess.get_process_address_space()
        self.PhysicalMemory = memory
        self.Offset = eprocess.obj_offset
        self.ImageBaseAddress = eprocess.Peb.ImageBaseAddress
        self.Peb = eprocess.Peb
        self.Modules = self.getModules(eprocess)
        self.SectionBaseAddress = eprocess.SectionBaseAddress
        # get all Threads belong to current process
        threads = []
        for thread in eprocess.ThreadListHead.list_of_type("_ETHREAD", "ThreadListEntry"):
            threads.append(Thread(thread, None))
        self.Threads = threads

        # get all vads belong to current process
        vads = []
        for vad in eprocess.VadRoot.traverse():
            vads.append(VAD(vad, memory, self.VirtualMemory))
        self.VADs = tuple(vads)

    @staticmethod
    def getModules(eprocess):
        modules = list()
        for module in eprocess.get_load_modules():
            modules.append(Module(module, eprocess))
        return modules

    def getVAD(self, base):
        """ Get the VAD representing a certain offset in the process space.

            Keyword arguments:
            base -- the offset inside the virtual address space
        """
        for vad in self.VADs:
            if base == vad.Start:
                return vad

    def read(self, base, length):
        """ Reads test_data from the virtual memory range of the process.

            Keyword arguments:
            base -- the offset in the adress space to read from
            length -- the amout of bytes to be read
        """
        data = self.VirtualMemory.zread(base, length)
        if not len(data) == length:
            return self.PhysicalMemory.zread(base, length)
        return data

    def __str__(self):
        return "Process #%d (%d): %s (%d vads)" % (self.Id,
                                                   self.Parent, self.Name, len(self.VADs))


class Module(object):
    def __init__(self, module, eprocess):
        self.module = module
        self.Offset = module.obj_vm.vtop(
            module.obj_offset)
        self.PID = int(eprocess.UniqueProcessId)
        self.BaseDllName = str(module.BaseDllName or '')
        self.DllBase = int(module.DllBase)
        self.Start = self.DllBase
        self.SizeOfImage = int(module.SizeOfImage)
        self.Size = self.SizeOfImage
        self.End = self.Start + self.Size
        self.FullDllName = str(module.FullDllName or '')
        self.LoadCount = int(module.LoadCount)

    def __contains__(self, vad):
        return self.Start <= vad.Start <= vad.End <= self.End


class VolatilityInterface:
    """ A class representing a memorydump progressed by Volatility.

        Keyword arguments:
        path -- the path to the dump to be analyzed
        profile -- the profile to parse the memory dump with (default 'WinXPSP2x86')
    """

    def __init__(self, path, profile='WinXPSP2x86', report=0):
        self.config = conf.ConfObject()
        registry.PluginImporter()
        registry.register_global_options(self.config, commands.Command)
        registry.register_global_options(self.config, addrspace.BaseAddressSpace)
        # self.config.parse_options()
        self.config.PROFILE = profile
        self.config.LOCATION = "file://" + path
        self.Memory = utils.load_as(self.config)

        logging.critical("[进程模块加载中]")
        self.Processes, self.backup = self.__getProcesses()

        logging.critical("[线程模块加载中]")
        self.Threads = self.__getThreads()
        if report:
            logging.critical("[镜像信息加载中]")
            self.Info = self.__getInfo()

            logging.critical("[命令行信息加载中]")
            # self.IEHistroy = self.__getIEHistory()
            self.CmdLine = self.__getCmdLine()

            logging.critical("[网络模块加载中]")
            self.Networks = self.__getNetwork()

            logging.critical("[注册表模块加载中]")
            self.Registry = self.__getRegistry()

    def __getProcesses(self, scan=False):
        """ Internal method to scan the memory for processes. """
        backup = {}
        output = []
        if not scan:
            plist = pslist(self.Memory)
            p = list(plist)
        else:
            _raw = []
            for offset, process, _ in psxview.PsXview(self.config).calculate():
                _raw.append(process)
            p = _raw
        for process in p:
            item = Process(process, self.Memory)
            backup[item.Id] = item
            output.append(item)
        return output, backup

    def __getThreads(self):
        """ Internal method to scan the memory for threads. """
        p = threads.Threads(self.config)
        return [Thread(thread[0], thread[1]) for thread in p.calculate()]

    def __getNetwork(self):
        """ Internal method to scan the memory for networks. """
        network = netscan.Netscan(self.config)
        return [Network(record[0], record[1], record[2], record[3], record[4], record[5]) for record in
                network.calculate()]

    def __getInfo(self):
        """ Internal method to get the image info """
        info = imageinfo.ImageInfo(self.config)
        result = [[item[0], item[2]] for item in info.calculate()]
        result[9][1] = str(hex(result[9][1]))
        result[10][1] = str(hex(result[10][1]))
        return result

    def __getRegistry(self):
        """ Internal method to get the Registry """
        regapi = registryapi.RegistryApi(self.config)
        regapi.set_current(hive_name="NTUSER.DAT", user="float")
        check_key = "SOFTWARE\\Microsoft\\windows\\CurrentVersion\\Run"
        result = ""
        for value, data in regapi.reg_yield_values(None, key=check_key):
            result += "{0:<50} {1:<20}\n".format(data, value)
        return result

    def __getCmdLine(self):
        """ Internal method to get cmdline infomation """
        cmd = cmdline.Cmdline(self.config)
        result = []
        for item in cmd.generator(cmd.calculate()):
            result.append(item[1])

        return result


'''
    def __getIEHistory(self):
        """ Internal method to get the ie history """
        history = iehistory.IEHistory(self.config)
        result = [item for item in history.calculate()]
        return result
'''
