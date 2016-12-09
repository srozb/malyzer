# -*- coding: utf-8 -*-

import string
import config
from winappdbg.win32 import *
from winappdbg import EventHandler, HexDump
from helper import hexprint
from winconst import *
from hookparser import HookParser
from logger import Logger
from storagepool import sp
from filedumper import FileDumper
from hookdispatcher import HookDispatcher

fd = FileDumper()
hd = HookDispatcher()
l = Logger(__name__)


class TracingEventHandler(EventHandler):
    HP = HookParser()
    apiHooks = HP.get_configured_hooks()

    def create_thread(self, event):
        tid = event.get_tid()
        sp.addThread(tid)
        if config.show_create_thread:
            l.conPrint("New thread created: {}".format(tid))
        l.debug("New thread created: {}".format(tid))

    def load_dll(self, event):
        module = event.get_module()
        mod_name = module.get_name()  # get_filename will return whole path
        sp.addModule(mod_name)
        l.debug("New module discovered: {}".format(mod_name))

    def create_process(self, event):
        proc = event.get_process()
        pid = proc.get_pid()
        img_name = proc.get_image_name()
        l.info("{} ({}) process discovered.".format(pid, img_name))

    def exit_process(self,event):
        pid = event.get_pid()
        try:
            fn = event.get_filename()
            ec = event.get_exit_code()
            l.info("{} ({}) exited with code: {}".format(pid, fn, ec))
        except KeyError:
            l.warn("{} unable to get_filename during proc exit".format(pid))

    def event(self,event):
        pid = event.get_pid()
        en = event.get_event_name()
        l.warn("{} unhandled event: {}".format(pid, en))

    def _isPrintable(self, buf):
        "return True if string contains only printable chars"
        printset = set(string.printable)
        return set(buf).issubset(printset)

    def peek(self, event, pointer, funicode=False):
        return event.get_process().peek_string(pointer, fUnicode=funicode)

    def npeek(self, event, pointer, bufsize):
        if (bufsize <= 0):
            return ""
        return event.get_process().read(pointer, bufsize)

    def writemem(self, event, address, buf):
        p = event.get_process()
        p.write(address, buf)

    def write_dword(self, event, address, buf):
        p = event.get_process()
        p.write_dword(address, buf)

    def resolvParams(self, event, params):
        buf = ""
        for p in params:
            if ((type(p) == type(long()) or type(p) == type(int())) and p >
                    10240):
                payload = self.peek(event, p)
                if self._isPrintable(payload):
                    buf += "\n" + payload + " "
                else:
                    buf += "\n" + hexprint(payload) + " "
            elif (type(p) == type(int()) or type(p) == type(long())):
                buf += str(p) + " "
            elif (len(str(p)) > 0):
                if self._isPrintable(p):
                    buf += p + " "
                else:
                    buf += hexprint(p) + " "
        return buf

    def post_CreateRemoteThread(self, event, retval):
        bits = event.get_process().get_bits()
        params = event.hook.get_params(event.get_tid())
        dwStackSize = params[2]
        StackSize = int(HexDump.integer(dwStackSize, bits))
        lpStartAddress = params[3]
        StartAddress = "0x" + HexDump.address(lpStartAddress, bits)
        lpThreadId = params[6]
        #ThreadId = event.get_process().read_uint(lpThreadId)
        #ThreadId = "0x" + HexDump.integer(ThreadId, bits)  # TODO
        buf = "StackSize: {}, StartAddress: {}".format(StackSize,
            StartAddress)
        hd.dispatch(event, "CreateRemoteThread", buf, "thread", StartAddress)

    def post_CreateThread(self, event, retval):
        bits = event.get_process().get_bits()
        params = event.hook.get_params(event.get_tid())
        dwStackSize = params[1]
        StackSize = int(HexDump.integer(dwStackSize, bits), 16)
        lpStartAddress = params[2]
        StartAddress = "0x" + HexDump.address(lpStartAddress, bits)
        lpThreadId = retval
        buf = "StackSize: {}, StartAddress: {}, ThreadId: {}".format(StackSize,
            StartAddress, lpThreadId)
        hd.dispatch(event, "CreateThread", buf, "thread", StartAddress)

    def post_ResumeThread(self, event, retval):
        bits = event.get_process().get_bits()
        params = event.hook.get_params(event.get_tid())
        handle = params[0]
        buf = "handle: {}".format(handle)
        hd.dispatch(event, "ResumeThread", buf, "thread", handle)

    def post_CreateRemoteThreadEx(self, event, retval):
        bits = event.get_process().get_bits()
        params = event.hook.get_params(event.get_tid())
        dwStackSize = params[2]
        StackSize = int(HexDump.integer(dwStackSize, bits))
        lpStartAddress = params[3]
        StartAddress = "0x" + HexDump.address(lpStartAddress, bits)
        lpThreadId = params[7]
        #ThreadId = event.get_process().read_uint(lpThreadId)
        #ThreadId = "0x" + HexDump.integer(ThreadId, bits)  # TODO
        buf = "StackSize: {}, StartAddress: {}".format(StackSize,
            StartAddress)
        hd.dispatch(event, "CreateRemoteThreadEx", buf, "thread", StartAddress)

    def post_LoadLibrary(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        lpFilename = self.peek(event, params[0])
        buf = "lpFilename: {}".format(lpFilename)
        hd.dispatch(event, "LoadLibrary", buf, "module", lpFilename)

    def pre_Sleep(self, event, retval, dwMilliseconds):
        buf = "Sleep: {}".format(dwMilliseconds)
        #esp = event.get_thread().get_sp()
        #param_offset = esp + 4
        #self.write_dword(event, param_offset, 100)  # 100 ms
        #TODO: make optional dwM rewrite
        hd.dispatch(event, "Sleep", buf, "thread", dwMilliseconds)

    def post_CreateProcessA(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        appName = self.peek(event, params[0])
        cmdLine = self.peek(event, params[1])
        #TODO: attribiute CREATE_SUSPENDED
        buf = "appName: {}, cmdLine: {}".format(appName, cmdLine)
        hd.dispatch(event, "CreateProcessA", buf, "process", appName)

    def post_CreateProcessW(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        appName = self.peek(event, params[0], funicode=True)
        cmdLine = self.peek(event, params[1], funicode=True)
        #TODO: attribiute CREATE_SUSPENDED
        buf = "appName: {}, cmdLine: {}".format(appName, cmdLine)
        hd.dispatch(event, "CreateProcessW", buf, "process", appName)

    def post_GetProcAddress(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        #hModule = self.peek(event, params[0])
        lpProcName = params[1]
        procAddr = "0x" + HexDump.address(retval, bits)
        #TODO: attribiute CREATE_SUSPENDED
        buf = "lpProcName: {}, ret_addr: {}".format(lpProcName, procAddr)
        hd.dispatch(event, "GetProcAddress", buf, "module", lpProcName)

    def post_WriteProcessMemory(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        dataLen = params[3]
        data = self.npeek(event, params[2], dataLen)
        dumped_file, digest, filetype = fd.dump("WriteProcessMemory", data)
        if dumped_file:
            buf = "dumped: {}, size: {} bytes, mime: {}".format(dumped_file,
                dataLen, filetype)
        else:
            buf = "not dumping/duplicate: {}, size: {} bytes".format(digest,
                dataLen)
        hd.dispatch(event, "WriteProcessMemory", buf, "process", digest)

    def post_CreateFileA(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        filename = self.peek(event, params[0])
        buf = "filename: {}".format(filename)
        hd.dispatch(event, "CreateFileA", buf, "filesystem", filename)

    def post_CreateFileW(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        filename = self.peek(event, params[0], funicode=True)
        buf = "filename: {}".format(filename)
        hd.dispatch(event, "CreateFileW", buf, "filesystem", filename)

    def post_WriteFile(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        dataLen = params[2]
        data = self.npeek(event, params[1], dataLen)
        dumped_file, digest, filetype = fd.dump("WriteFile", data)
        if dumped_file:
            buf = "dumped: {}, size: {} bytes, mime: {}".format(dumped_file,
                dataLen, filetype)
        else:
            buf = "not dumping/duplicate: {}, size: {} bytes".format(digest,
                dataLen)
        hd.dispatch(event, "WriteFile", buf, "filesystem", digest)

    def DISABLED_post_ReadFile(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        dataLen = params[2]
        data = self.npeek(event, params[1], dataLen)
        buf = "data: {}".format(hexprint(data))
        hd.dispatch(event, "ReadFile", buf, "filesystem")

    def post_FindFirstFileA(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        filename = self.peek(event, params[0])
        buf = "filename: {}".format(filename)
        hd.dispatch(event, "FindFirstFileA", buf, "filesystem", filename)

    def post_FindFirstFileW(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        filename = self.peek(event, params[0], funicode=True)
        buf = "filename: {}".format(filename)
        hd.dispatch(event, "FindFirstFileW", buf, "filesystem", filename)

    def post_HttpAddRequestHeadersA(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        headers = self.peek(event, params[1])
        buf = "headers: {}".format(headers)
        hd.dispatch(event, "HttpAddRequestHeadersA", buf, "network")

    def post_HttpAddRequestHeadersW(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        headers = self.peek(event, params[1], funicode=True)
        buf = "headers: {}".format(headers)
        hd.dispatch(event, "HttpAddRequestHeadersW", buf, "network")

    def post_WinHttpConnect(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        ip = self.peek(event, params[1])
        buf = "host: {}".format(ip)
        hd.dispatch(event, "WinHttpConnect", buf, "network", ip)

    def post_WinHttpOpenRequest(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        uri = self.peek(event, params[1])
        buf = "URI: {}".format(uri)
        hd.dispatch(event, "WinHttpOpenRequest", buf, "network", ip)

    def post_inet_ntoa(self, event, retval):
        #params = event.hook.get_params(event.get_tid())
        ip = self.peek(event, retval)
        buf = "IP: {}".format(ip)
        hd.dispatch(event, "inet_ntoa", buf, "network", ip)

    def post_CertNameToStrW(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        psz = self.peek(event, params[3], funicode=True)
        buf = "psz: {}".format(psz)
        hd.dispatch(event, "CertNameToStrW", buf, "crypto", psz)

    def post_getaddrinfo(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        addr = self.peek(event, params[0])
        buf = "addr: {}".format(addr)
        hd.dispatch(event, "getaddrinfo", buf, "network", addr)

    def post_RegCreateKeyExA(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        hKey = params[0]
        key_name = reg_hkey[hKey] if reg_hkey.has_key(hKey) else hex(hKey)
        sub_key = event.get_process().peek_string(params[1])
        key_name = "%s\\%s" % (key_name, sub_key)
        hd.dispatch(event, "RegCreateKeyExA", key_name, "registry", sub_key)

    def post_RegCreateKeyExW(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        hKey = params[0]
        key_name = reg_hkey[hKey] if reg_hkey.has_key(hKey) else hex(hKey)
        #sub_key = event.get_process().peek_string(params[1])
        sub_key = self.peek(event, params[1], funicode=True)
        key_name = "%s\\%s" % (key_name, sub_key)
        hd.dispatch(event, "RegCreateKeyExW", key_name, "registry", sub_key)

    def post_RegCreateKeyA(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        hKey = params[0]
        key_name = reg_hkey[hKey] if reg_hkey.has_key(hKey) else hex(hKey)
        sub_key = event.get_process().peek_string(params[1])
        key_name = "%s\\%s" % (key_name, sub_key)
        hd.dispatch(event, "RegCreateKeyA", key_name)
    def post_RegCreateKeyW(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        hd.dispatch(event, "RegCreateKeyW", self.resolvParams(event, params),
            "registry")

    def post_CreateServiceA(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        lpServiceName = self.peek(event, params[1])
        lpDisplayName = self.peek(event, params[2])
        buf = "ServiceName: {}, DisplayName: {}".format(lpServiceName,
            lpDisplayName)
        hd.dispatch(event, "CreateServiceA", buf, "service", lpServiceName)

    def post_CreateServiceW(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        lpServiceName = self.peek(event, params[1], funicode=True)
        lpDisplayName = self.peek(event, params[2], funicode=True)
        buf = "ServiceName: {}, DisplayName: {}".format(lpServiceName,
            lpDisplayName)
        hd.dispatch(event, "CreateServiceW", buf, "service", lpServiceName)

    def post_RegOpenKeyExA(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        hKey = params[0]
        sub_key = event.get_process().peek_string(params[1])
        hkey_str = reg_hkey[hKey] if reg_hkey.has_key(hKey) else hex(hKey)
        key_name = "%s\\%s" % (hkey_str, sub_key)
        hd.dispatch(event, "RegOpenKeyExA", key_name, "registry", sub_key)

    def post_RegOpenKeyExW(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        hKey = params[0]
        sub_key = self.peek(event, params[1], funicode=True)
        hkey_str = reg_hkey[hKey] if reg_hkey.has_key(hKey) else hex(hKey)
        key_name = "%s\\%s" % (hkey_str, sub_key)
        hd.dispatch(event, "RegOpenKeyExW", key_name, "registry", sub_key)

    def post_RegOpenKeyA(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        hd.dispatch(event, "RegOpenKeyA", self.resolvParams(event, params),
            "registry")

    def post_RegOpenKeyW(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        hd.dispatch(event, "RegOpenKeyW", self.resolvParams(event, params),
            "registry")

    def post_WSASendW(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        hd.dispatch(event, "WSASendW", self.resolvParams(event, params),
            "network")

    def post_WSASendA(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        hd.dispatch(event, "WSASendA", self.resolvParams(event, params),
            "network")

    def post_WSAConnect(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        hd.dispatch(event, "WSAConnect", self.resolvParams(event, params),
            "network")

    def post_WSAConnectBtName(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        remote_addr = self.npeek(event, params[6], params[5])
        buf = "remote_addr:{}".format(remote_addr)
        hd.dispatch(event, "WSAConnectByName", buf, "network")

    def post_PR_Write(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        pointer = params[1]
        bufsize = params[2]
        if (bufsize > 128):
            bufsize = 128
        buf = self.npeek(event, pointer, bufsize)
        hd.dispatch(event, "PR_Write", buf, "network")

    def post_PR_Read(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        pointer = params[1]
        bufsize = params[2]
        if (bufsize > 128):
            bufsize = 128
        buf = self.npeek(event, pointer, bufsize)
        hd.dispatch(event, "PR_Read", buf, "network")

    def post_PFXExportCertStore(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        hd.dispatch(event, "PFXExportCertStore",
            self.resolvParams(event, params), "crypto")

    def post_PFXImportCertStore(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        szPassword = self.peek(event, params[1])
        buf = "szPassword: {}".format(szPassword)
        hd.dispatch(event, "PFXImportCertStore", buf, "network")

    def post_ShellExecuteA(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        hd.dispatch(event, "ShellExecuteA", self.resolvParams(event, params),
            "shell")

    def post_ShellExecuteW(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        hd.dispatch(event, "ShellExecuteW", self.resolvParams(event, params),
            "shell")

    def DISABLED_post_HashData(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        hd.dispatch(event, "HashData", self.resolvParams(event, params),
            "crypto")

    def post_PathFindFileNameA(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        inPath = self.peek(event, params[0])
        hd.dispatch(event, "PathFindFileNameA", inPath, "filesystem", inPath)

    def post_SHDeleteKeyA(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        hd.dispatch(event, "SHDeleteKeyA", self.resolvParams(event, params),
            "crypto")

    def post_CryptHashData(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        hd.dispatch(event, "CryptHashData", str(params), "crypto")

    def post_CryptCreateHash(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        Algid = params[1]
        hKey = params[2]
        buf = "Algid:{} hKey:{}".format(Algid, hKey)
        hd.dispatch(event, "CryptCreateHash", buf, "crypto")

    def post_CryptEncrypt(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        hd.dispatch(event, "CryptEncrypt", self.resolvParams(event, params),
            "crypto")

    def post_CryptDecrypt(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        hd.dispatch(event, "CryptDecrypt", self.resolvParams(event, params),
            "crypto")

    def pre_CryptProtectData(self, event, retval, *args, **kwargs):
        params = event.hook.get_params(event.get_tid())
        hd.dispatch(event, "CryptProtectData", self.resolvParams(event, params),
            "crypto")

    def post_CryptUnprotectData(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        hd.dispatch(event, "CryptUnprotectData", self.resolvParams(event, params),
            "crypto")

    def post_CertOpenStore(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        hd.dispatch(event, "CryptOpenStore", self.resolvParams(event, params),
            "crypto")

    def post_DnsQuery_W(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        hd.dispatch(event, "DnsQuery_W", self.resolvParams(event, params),
            "network")

    def post_DnsQuery_A(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        query = params[0]
        hd.dispatch(event, "DnsQuery_A", self.resolvParams(event, params),
            "network", query)

    def post_DnsQueryEx_W(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        query = params[0]
        hd.dispatch(event, "DnsQueryEx_W", self.resolvParams(event, params),
            "network", query)

    def post_gethostbyname(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        hd.dispatch(event, "gethostbyname", self.resolvParams(event, params),
            "network")

    def post_WSAStartup(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        hd.dispatch(event, "WSAStartup", self.resolvParams(event, params),
            "network")

    def DISABLED_pre_HttpOpenRequestA(self, event, ra, hConnect, lpszVerb,
            lpszObjectName, lpszVersion, lpszReferer, lplpszAcceptTypes,
            dwFlags, dwContext):
        uri = self.peek(event, lpszObjectName)
        buf = "HttpOpenRequestA({})\t{}".format(lpszObjectName, uri)
        l.conPrint(buf)

    def post_HttpOpenRequestA(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        lpszVerb = self.peek(event, params[1])
        lpszObjectName = self.peek(event, params[2])
        buf = "{} {}".format(lpszVerb, lpszObjectName)
        hd.dispatch(event, "HttpOpenRequestA", buf, "network", lpszObjectName)

    def post_HttpOpenRequestW(self, event, retval):
        params = event.hook.get_params(event.get_tid())
        lpszVerb = self.peek(event, params[1], funicode=True)
        lpszObjectName = self.peek(event, params[2], funicode=True)
        buf = "{} {}".format(lpszVerb, lpszObjectName)
        hd.dispatch(event, "HttpOpenRequestW", buf, "network", lpszObjectName)

    def DISABLED_pre_HttpOpenRequestW(self, event, ra, hConnect, lpszVerb,
            lpszObjectName, lpszVersion, lpszReferer, lplpszAcceptTypes,
            dwFlags, dwContext):
        '''uri = self.peek(event, lpszObjectName, funicode=True)
        buf = "HttpOpenRequestW({})\t{}".format(lpszObjectName, uri)
        logToConsole(buf)'''

    def pre_HttpSendRequestA(self, event, ra, hRequest, lpszHeaders,
            dwHeadersLength, lpOptional, dwOptionalLength):
        headers = self.peek(event, lpszHeaders)
        optional = hexprint(self.peek(event, lpOptional))
        buf = "headers: {} optional: {}".format(headers, optional)
        hd.dispatch(event, "HttpSendRequestA", buf, "network")

    def pre_HttpSendRequestW(self, event, ra, hRequest, lpszHeaders,
            dwHeadersLength, lpOptional, dwOptionalLength):
        headers = self.peek(event, lpszHeaders, funicode=True)
        optional = hexprint(self.peek(event, lpOptional, funicode=True))
        buf = "headers: {} optional: {}".format(headers, optional)
        hd.dispatch(event, "HttpSendRequestW", buf, "network")

    def pre_InternetConnectA(self, event, ra, hInternet, lpszServerName,
            nServerPort, lpszUsername, lpszPassword, dwService,
            dwFlags, dwContext):
        ServerName = self.peek(event, lpszServerName)
        ServerPort = self.peek(event, nServerPort)
        if (not ServerPort):
            ServerPort = "DEFAULT"
        buf = "{}:{}".format(ServerName, ServerPort)
        hd.dispatch(event, "InternetConnectA", buf, "network", ServerName)

    def pre_InternetConnectW(self, event, ra, hInternet, lpszServerName,
            nServerPort, lpszUsername, lpszPassword, dwService,
            dwFlags, dwContext):
        ServerName = self.peek(event, lpszServerName, funicode=True)
        ServerPort = self.peek(event, nServerPort, funicode=True)
        if (not ServerPort):
            ServerPort = "DEFAULT"
        buf = "{}:{}".format(ServerName, ServerPort)
        hd.dispatch(event, "InternetConnectW", buf, "network", ServerName)

    def DISABLED_pre_MessageBoxA(self, event, ra, hWnd, lpText, lpCaption, uType):
        Text = self.peek(event, lpText, funicode=False)
        Caption = self.peek(event, lpCaption, funicode=False)
        buf = "MessageBoxA - {}: {}".format(Caption, Text)
        logToConsole(buf)

    def DISABLED_pre_MessageBoxW(self, event, ra, hWnd, lpText, lpCaption, uType):
        Text = self.peek(event, lpText, funicode=True)
        Caption = self.peek(event, lpCaption, funicode=True)
        buf = "MessageBoxW - {}: {}".format(Caption, Text)
        logToConsole(buf)

#duplicated? ->

    def pre_CryptEncrypt(self, event, ra, hKey, hHash, Final, dwFlags, pbData,
            pdwDataLen, dwBufLen):
        Data = self.npeek(event, pbData, pdwDataLen)
        hd.dispatch(event, "CryptEncrypt", Data, "crypto")

    def pre_WSASendW(self, event, ra, s, lpBuffers, dwBufferCount,
            lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine):
        #Data = self.peek(event, pbData, funicode=False)
        buf = " "
        hd.dispatch(event, "WSASendW", buf, "network")

