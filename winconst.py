# -*- coding: utf-8 -*-

reg_hkey = {
    0x80000000 : 'HKEY_CLASSES_ROOT',
    0x80000001 : 'HKEY_CURRENT_USER',
    0x80000002 : 'HKEY_LOCAL_MACHINE',
    0x80000003 : 'HKEY_USERS',
    0x80000004 : 'HKEY_PERFORMANCE_DATA',
    0x80000005 : 'HKEY_CURRENT_CONFIG',
    }

#Hooks


hooks = {
    'kernel32.dll' : [
        ('CreateThread',              6),
        ('CreateRemoteThread',        7),
        ('CreateRemoteThreadEx',      8),
        ('CreateFileA',               7),
        ('CreateFileW',               7),
        ('WriteFile',                 5),
        ('ReadFile',                  5),
        ('FindFirstFileA',            2),
        ('FindFirstFileW',            2),
        ('LoadLibrary',               1),
        ('Sleep',                     1),
        ('CreateThread',              6),
        ('CreateProcessA',            10),
        ('CreateProcessW',            10),
        ('ResumeThread',              1),
        ('WriteProcessMemory',        5),
        ('GetProcAddress',            2),
    ],
    'wininet.dll' : [
        ('HttpOpenRequestA',          8),
        ('HttpOpenRequestW',          8),
        ('InternetConnectA',          8),
        ('InternetConnectW',          8),
        ('HttpSendRequestA',          5),
        ('HttpSendRequestW',          5),
        ('InternetReadFile',          4),
        ('InternetWriteFile',         4),
        ('HttpAddRequestHeadersA',    4),
        ('HttpAddRequestHeadersW',    4),
    ],
    'user32.dll' : [
        ('MessageBoxA',               4),
        ('MessageBoxW',               4),
    ],
    'advapi32.dll' : [
        ( 'CryptHashData',            4),
        ( 'CryptCreateHash',          5),
        ( 'CryptEncrypt',             7),
        ( 'CryptDecrypt',             6),
        ( 'RegCreateKeyExA' ,         9),
        ( 'RegCreateKeyExW' ,         9),
        ( 'RegCreateKeyA'   ,         3),
        ( 'RegCreateKeyW'   ,         3),
        ( 'CreateServiceA',          13),
        ( 'CreateServiceW',          13),
        ( 'RegOpenKeyA',              5),
        ( 'RegOpenKeyW',              5),
        ( 'RegOpenKeyExA',            5),
        ( 'RegOpenKeyExW',            5),
    ],
    'crypt32.dll' : [
        ( 'CryptProtectData',         7),
        ( 'CryptUnprotectData',       7),
        ( 'CertOpenStore',            5),
        ( 'PFXExportCertStore',       4),
        ( 'PFXImportCertStore',       3),
        ('CertNameToStrW',            5),
    ],
    'dnsapi.dll' : [
        ( 'DnsQuery_W',               6),
        ('DnsQuery_A',                6),
        ('DnsQueryEx_W',              3),
    ],
    'ole32.dll' : [
        ( 'CoCreateInstance',         5),
        ( 'CoCreateGuid',             1),
        ( 'StringFromGUID2',          3),
    ],
    'ws2_32.dll' : [
        ( 'WSAStartup',               2),
        ( 'gethostbyname',            2),
        ( 'WSASSendW',                7),
        ('WSAConnect',                3),
        ('WSASendA',                  7),
        ('WSAConnectByName',          9),
        ('inet_ntoa',                 1),
        ('getaddrinfo',               4),
    ],
    'shlwapi.dll' : [
        ( 'HashData',                 4),
        ( 'PathFindFileNameA',        1),
        ( 'PathFindFileNameW',        1),
        ( 'SHDeleteKeyA',             2),
        ( 'SHDeleteKeyW',             2),
    ],
    'shell32.dll' : [
        ( 'ShellExecuteA',            6),
        ( 'ShellExecuteW',            6),
    ],
    'nss3.dll' : [
        ( 'PR_Write',                 3),
        ( 'PR_Read',                  3),
    ],
    'winhttp.dll' : [
        ('WinHttpConnect',            4),
        ('WinHttpOpenRequest',        7),
    ],
}