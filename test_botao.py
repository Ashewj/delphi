import pymem.process as process
import pymem

import ctypes.wintypes as wintypes
import pefile
import psutil
import ctypes
import frida
import sys
import re

import contextlib
#import cyminhook
import win32api
import win32con

def get_process_path_by_name(process_name: str) -> str:
    for proc in psutil.process_iter(['name', 'exe']):
        if proc.info['name'] and proc.info['name'].lower() == process_name.lower():
            return proc.info['exe']
    return None

def va_to_bytes(p, va, m = 32):
    rva = va - p.OPTIONAL_HEADER.ImageBase
    file_offset = p.get_offset_from_rva(rva)
    return p.__data__[file_offset:file_offset + m]

def rnonp(data: bytes) -> bytes:
    to_replace = b"!@#$%^&*()[]{}"
    trans_table = bytearray(range(256))
    for b in to_replace:
        trans_table[b] = ord('.')
    return data.translate(bytes(trans_table))

p_name = 'Project1.exe'
p_path = get_process_path_by_name(p_name)

pm = pymem.Pymem(p_name)
pe = pefile.PE(p_path)

report_previewmodal_pattern = rnonp(va_to_bytes(pe, 0x96B3E0, 32).translate(bytes.maketrans(b'\x00', b'.')))
button1 = rnonp(va_to_bytes(pe, 0x9AAB70, 32).translate(bytes.maketrans(b'\x00', b'.')))

TRLCustomReport_PreviewModal = pymem.pattern.pattern_scan_all(pm.process_handle, report_previewmodal_pattern, return_multiple=False)
TForm1_Button1Click = pymem.pattern.pattern_scan_all(pm.process_handle, button1, return_multiple=False)

def on_message(message, data):
    print("[%s] => %s" % (message, data))

session = frida.attach(p_name)
script = session.create_script(
    f"""
    var printtt = new NativeFunction(ptr({TForm1_Button1Click}), 'void', []);
    console.log('click');
    printtt();
    """
)
script.on('message', on_message)
script.load()
#sys.stdin.read()
#session.detach()