import pefile
import psutil
import re 

IMAGE_DIRECTORY_ENTRY_RESOURCE = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']

def __va_to_offset(p: pefile.PE, va: int) -> int:
        return p.get_offset_from_rva(va - p.OPTIONAL_HEADER.ImageBase)

def is_loaded(pe: pefile.PE, va: int) -> bool:
    try:
        #offset = __va_to_offset(pe, va)
        #return offset < len(pe.__data__)

        image_base = pe.OPTIONAL_HEADER.ImageBase
        rva = va - image_base
        offset = pe.get_offset_from_rva(rva)
        _ = pe.__data__[offset]
        return True
    except Exception:
        return False
    
def is_mapped(pe: pefile.PE, va: int) -> bool:
    try:
        image_base = pe.OPTIONAL_HEADER.ImageBase
        for section in pe.sections:
            start = image_base + section.VirtualAddress
            end = start + section.Misc_VirtualSize
            if start <= va < end:
                return True
    except Exception:
        return False

def Byte(p: pefile.PE, va: int) -> int:
    offset = __va_to_offset(p, va)
    return p.__data__[offset]

def Word(p: pefile.PE, va: int) -> int:
    offset = __va_to_offset(p, va)
    data = p.__data__[offset : offset + 2]
    return data[0] | (data[1] << 8)

def Dword(p: pefile.PE, va: int) -> int:
    offset = __va_to_offset(p, va)
    data = p.__data__[offset : offset + 4]
    return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24)

def Qword(p: pefile.PE, va: int) -> int:
    offset = __va_to_offset(p, va)
    data = p.__data__[offset : offset + 8]
    return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24) | (data[4] << 32) | (data[5] << 40) | (data[6] << 48) | (data[7] << 56)

##############################################################################################################################

def MakeByte(p: pefile.PE, va: int) -> int:
    value = Byte(p, va)
    #print(f"[MakeByte] 0x{va:X}: {value:#04x}")
    return value

def MakeWord(p: pefile.PE, va: int) -> int:
    value = Word(p, va)
    #print(f"[MakeWord] 0x{va:X}: {value:#06x}")
    return value

def MakeDword(p: pefile.PE, va: int) -> int:
    value = Dword(p, va)
    #print(f"[MakeDword] 0x{va:X}: {value:#010x}")
    return value

def MakeQword(p: pefile.PE, va: int) -> int:
    value = Qword(p, va)
    #print(f"[MakeQword] 0x{va:X}: {value:#018x}")
    return value

def get_segm_name(pe, va: int):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    for section in pe.sections:
        start = image_base + section.VirtualAddress
        end = start + section.Misc_VirtualSize
        if start <= va < end:
            return section.Name.rstrip(b'\x00').decode()
    return None

def find_bytes(pe: pefile.PE, pattern: bytes, section_name: str = None, start_offset: int = 0) -> int:
    data = pe.__data__
    imagebase = pe.OPTIONAL_HEADER.ImageBase
 
    if start_offset != 0:
        start_offset = pe.get_offset_from_rva(start_offset - imagebase)
       
    #caller = inspect.stack()[1]
    #caller_info = f"{caller.filename}:{caller.lineno} in {caller.function}"
    #print(f"find_bytes {start_offset}  <-- called from {caller_info}")

    if section_name:
        #print(f"{section_name} | called from {caller_info}")
        for section in pe.sections:
            name = section.Name.rstrip(b'\x00').decode()
            if name == section_name:
                section_data = section.get_data()
                match = re.search(re.escape(pattern), section_data[start_offset:])
                if match:
                    offset = section.PointerToRawData + start_offset + match.start()
                    rva = pe.get_rva_from_offset(offset)
                    return imagebase + rva
        return 0
    else:
        match = re.search(re.escape(pattern), data[start_offset:])
        if match:
            offset = start_offset + match.start()
            rva = pe.get_rva_from_offset(offset)
            return imagebase + rva
        return 0
    
def find_bytes_backward(pe: pefile.PE, pattern: bytes, section_name: str = None, start_offset: int = 0) -> int:
    data = pe.__data__
    imagebase = pe.OPTIONAL_HEADER.ImageBase

    if start_offset != 0:
        start_offset = pe.get_offset_from_rva(start_offset - imagebase)

    #caller = inspect.stack()[1]
    #caller_info = f"{caller.filename}:{caller.lineno} in {caller.function}"

    if section_name:
        #print(f"{section_name} | called from {caller_info}")
        for section in pe.sections:
            name = section.Name.rstrip(b'\x00').decode()
            if name == section_name:
                section_data = section.get_data()
                matches = list(re.finditer(re.escape(pattern), section_data[:start_offset or None]))
                if matches:
                    match = matches[0] # -1 not bueno
                    offset = section.PointerToRawData + match.start()
                    rva = pe.get_rva_from_offset(offset)
                    return imagebase + rva
        return 0
    else:
        matches = list(re.finditer(re.escape(pattern), data[:start_offset or None]))
        if matches:
            match = matches[0] # -1 not bueno
            offset = match.start()
            rva = pe.get_rva_from_offset(offset)
            return imagebase + rva
        return 0

def FindRef_Dword(pe: pefile.PE, fromAddrOrSection, dwordToFind: int, search_forward: bool = True) -> int:
    stringToFind = dwordToFind.to_bytes(4, byteorder='little')
    
    if isinstance(fromAddrOrSection, int):
        # It's a virtual address
        start_va = fromAddrOrSection
        for section in pe.sections:
            start = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
            end = start + section.Misc_VirtualSize
            if start <= fromAddrOrSection < end:
                section_name = section.Name.rstrip(b'\x00').decode(errors='ignore')
                break
    elif hasattr(fromAddrOrSection, 'Name') and hasattr(fromAddrOrSection, 'VirtualAddress'):
        # It's a section object
        section = fromAddrOrSection
        section_name = section.Name.rstrip(b'\x00').decode(errors='ignore')
        start_va = 0 #pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
    else:
        raise TypeError("fromAddrOrSection must be a section object or a virtual address (int)")

    if search_forward:
        return find_bytes(pe, stringToFind, section_name, start_va) 
    else:
        return find_bytes_backward(pe, stringToFind, section_name, start_va)
    
def FindRef_Qword(pe: pefile.PE, fromAddrOrSection, qwordToFind: int, search_forward: bool = True) -> int:
    stringToFind = qwordToFind.to_bytes(8, byteorder='little')
    
    """stringToFind = str()
    for i in range(8):
        stringToFind += "%02X " % ((qwordToFind >> 8*i) & 0xff)
    stringToFind = bytes.fromhex(stringToFind)"""

    if isinstance(fromAddrOrSection, int):
        # It's a virtual address
        start_va = fromAddrOrSection
        for section in pe.sections:
            start = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
            end = start + section.Misc_VirtualSize
            if start <= fromAddrOrSection < end:
                section_name = section.Name.rstrip(b'\x00').decode(errors='ignore')
                break
    elif hasattr(fromAddrOrSection, 'Name') and hasattr(fromAddrOrSection, 'VirtualAddress'):
        # It's a section object
        section = fromAddrOrSection
        section_name = section.Name.rstrip(b'\x00').decode(errors='ignore')
        start_va = 0 #pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
    else:
        raise TypeError("fromAddrOrSection must be a section object or a virtual address (int)")

    if search_forward:
        return find_bytes(pe, stringToFind, section_name, start_va) 
    else:
        return find_bytes_backward(pe, stringToFind, section_name, start_va)
    
##############################################################################################################################

def FixName(name: str) -> str:
    name = "".join(i for i in name if ord(i) < 128)
    for elem in [".", "<", ">", ":", ",", "%"]:
        if elem in name:
            name = name.replace(elem, "_")
    return name

def GetStr(p: pefile.PE, va: int, length: int = None) -> str:
    offset = __va_to_offset(p, va)
    data = p.__data__[offset:]
    if length is not None:
        data = data[:length]
    try:
        return data.split(b'\x00')[0].decode('utf-8', errors='ignore')
    except Exception:
        return ""

def GetStr_PASCAL(p: pefile.PE, va: int) -> str:
    strlen = Byte(p, va)
    return GetStr(p, va + 1, strlen)

def MakeStr(p: pefile.PE, start_va: int, end_va: int = None) -> str:
    offset = __va_to_offset(p, start_va)
    data = p.__data__[offset:]

    # If end_va not provided, find the null-terminator
    if end_va is None:
        string = data.split(b'\x00')[0]
    else:
        end_offset = __va_to_offset(p, end_va)
        string = p.__data__[offset:end_offset]

    try:
        decoded = string.decode("utf-8", errors="ignore")
    except UnicodeDecodeError:
        decoded = "<invalid utf-8>"

    #print(f"[MakeStr] 0x{start_va:X}: '{decoded}'")
    return decoded

def MakeStr_PASCAL(p: pefile.PE, va: int) -> str:
    strlen = Byte(p, va)
    # Pascal string is length-prefixed and ends at va + 1 + strlen
    return MakeStr(p, va + 1, va + 1 + strlen)

named_addresses = {}

def set_name(addr: int, name: str) -> None:
    named_addresses[addr] = name

def get_name(addr: int) -> str:
    return named_addresses.get(addr, f"sub_{addr:06X}") 

def MakeName(addr: int, name: str) -> None:
    fixed_name = FixName(name)
    set_name(addr, fixed_name)
    
def DemangleFuncName(funcAddr: int) -> str:
    funcName = get_name(funcAddr)

    if "@" in funcName:
        funcNameSplitted = funcName.split("$")
        names = funcNameSplitted[0]

        parameters = ""
        if "$" in funcName:
            parameters = funcNameSplitted[1]

        namesSplitted = names.split("@")

        if namesSplitted[-1] == "":
            if namesSplitted[-2] == "":
                print(f"[WARNING] FixFuncName: Unmangling error - {funcName}")
            elif parameters == "bctr":
                funcName = namesSplitted[-2] + "_Constructor"
            elif parameters == "bdtr":
                funcName = namesSplitted[-2] + "_Destructor"
            else:
                print(f"[WARNING] FixFuncName: Unmangling error - {funcName}")
        elif namesSplitted[-1] == "":
            funcName = namesSplitted[-3] + "_" + namesSplitted[-1]
        else:
            funcName = namesSplitted[-2] + "_" + namesSplitted[-1]

        MakeName(funcAddr, FixName(funcName))

    #print('TODO: Better get_name(funcAddr)')
    return get_name(funcAddr)

##############################################################################################################################

def GetCustomWord(p: pefile.PE, addr: int, wordSize: int = 4) -> int:
    if wordSize == 8:
        return Qword(p, addr)
    elif wordSize == 4:
        return Dword(p, addr)
    else:
        raise Exception("Unsupported word size!")

def MakeCustomWord(p: pefile.PE, addr: int, wordSize: int = 4) -> None:
    if wordSize == 8:
        MakeQword(p, addr)
    elif wordSize == 4:
        MakeDword(p, addr)
    else:
        raise Exception("Unsupported word size!")
    
def get_process_path_by_name(process_name: str) -> str:
    for proc in psutil.process_iter(['name', 'exe']):
        if proc.info['name'] and proc.info['name'].lower() == process_name.lower():
            return proc.info['exe']
    return None

def get_bytes(p, va: int, size: int) -> bytes:
    offset = __va_to_offset(p, va)
    return p.__data__[offset:offset + size]

def Is64bit(pe: pefile.PE) -> bool:
    return pe.FILE_HEADER.Machine == 0x8664  # IMAGE_FILE_MACHINE_AMD64

def Is32bit(pe: pefile.PE) -> bool:
    return pe.FILE_HEADER.Machine == 0x14c  # IMAGE_FILE_MACHINE_I386

def GetProcessorWordSize(pe: pefile.PE) -> int:
    if Is64bit(pe):
        return 8
    elif Is32bit(pe):
        return 4
    else:
        raise Exception("Unsupported word size!")
    
def GetApplicationClassAddr(pe: pefile.PE) -> int:
    # TApplication#
    strTApplicationAddr = find_bytes(pe, bytes.fromhex("0C 54 41 70 70 6C 69 63 61 74 69 6F 6E"))

    if strTApplicationAddr != -1:
        if Is32bit(pe):
            addr = FindRef_Dword(
                pe,
                strTApplicationAddr,
                strTApplicationAddr,
                False
            )

            if addr != -1:
                return addr - 0x20

        if Is64bit(pe):
            addr = FindRef_Qword(
                pe,
                strTApplicationAddr,
                strTApplicationAddr,
                False
            )

            if addr != -1:
                return addr - 0x40

    return -1

class DFMFinder:
    def __init__(self, pe: pefile.PE):
        self.__pe = pe
        self.__rsrcSecAddr = self.__GetResourceSectionAddress()
        self.__DFMlist = list()
        self.__ExtractDFM()

    def GetDFMList(self) -> list[tuple[int, int]]:
        return self.__DFMlist
    
    def __CheckDFMSignature(self, addr: int) -> bool:
        if chr(Byte(self.__pe, addr)) == "T" and \
           chr(Byte(self.__pe, addr + 1)) == "P" and \
           chr(Byte(self.__pe, addr + 2)) == "F" and \
           chr(Byte(self.__pe, addr + 3)) == "0":
            return True
        else:
            return False
        
    def __GetResourceSectionAddress(self) -> int:
        resourceDirectoryRVA = self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress
        if resourceDirectoryRVA:
            return self.__pe.OPTIONAL_HEADER.ImageBase + resourceDirectoryRVA
        return 0

    def __GetRCDATAAddr(self) -> int:
        numOfDirEntries = self.__GetNumberOfDirEntries(self.__rsrcSecAddr)
        addr = self.__rsrcSecAddr + 16
        for i in range(numOfDirEntries):
            # RCDATA
            if Dword(self.__pe, addr) == 10 and Dword(self.__pe, addr + 4) & 0x80000000 != 0:
                return self.__rsrcSecAddr + (Dword(self.__pe, addr + 4) & 0x7FFFFFFF)
            addr += 8
        return 0
    
    def __GetNumberOfDirEntries(self, tableAddr: int) -> int:
        return Word(self.__pe, tableAddr + 12) + Word(self.__pe, tableAddr + 14)

    def __ExtractDFMFromResource(self) -> None:
        print("[INFO] Searching for DFM in loaded resource section...")

        if self.__rsrcSecAddr == 0:
            print("[INFO] The resource directory is empty.")
            return
        
        if self.__rsrcSecAddr != -1:
            RCDATAaddr = self.__GetRCDATAAddr()
            
            if RCDATAaddr != 0:
                RCDATAaddrEntryCount = self.__GetNumberOfDirEntries(RCDATAaddr)
                addr = RCDATAaddr + 16

                for i in range(RCDATAaddrEntryCount):
                    if Dword(self.__pe, addr) & 0x80000000 != 0:
                        strAddr = (self.__rsrcSecAddr
                                   + (Dword(self.__pe, addr) & 0x7FFFFFFF))

                        if Dword(self.__pe, addr + 4) & 0x80000000 != 0:
                            dirTableAddr = (self.__rsrcSecAddr
                                            + (Dword(self.__pe, addr + 4) & 0x7FFFFFFF))

                            if self.__GetNumberOfDirEntries(dirTableAddr) == 1:
                                DFMDataAddr = (self.__pe.OPTIONAL_HEADER.ImageBase
                                               + Dword(self.__pe, self.__rsrcSecAddr
                                               + Dword(self.__pe, dirTableAddr + 20)))

                                DFMDataSizeAddr = (self.__rsrcSecAddr
                                                   + Dword(self.__pe, dirTableAddr + 20)
                                                   + 4)
                                DFMDataSize = Dword(self.__pe, DFMDataSizeAddr)

                                if self.__CheckDFMSignature(DFMDataAddr):
                                    self.__DFMlist.append((DFMDataAddr, DFMDataSize))
                    addr += 8
            else:
                print("[WARNING] The resource section seems to be corrupted!")
        else:
            print("[WARNING] The resource section not found! Make sure the resource section is loaded correctly.")

    def __ExtractDFMFromBinary(self) -> None:
        print("[INFO] Searching for DFM in loaded binary...")

        self.__DFMlist = list()
        startAddr = 0
        counter = 0
        
        while True:
            # 0x0TPF0
            dfmAddr = find_bytes(self.__pe, bytes.fromhex("00 54 50 46 30"), None, startAddr)
            if dfmAddr == 0:
                break

            if counter != 0 and Byte(self.__pe, dfmAddr + 5) != 0:  # FP
                print(f"[INFO] Found DFM: 0x{dfmAddr:x}")
                self.__DFMlist.append((dfmAddr + 1, 10000000))

            counter += 1
            startAddr = dfmAddr + 1
        
    def __ExtractDFM(self) -> None:
        self.__ExtractDFMFromResource()

        if len(self.__DFMlist) == 0:
            self.__ExtractDFMFromBinary()

        if len(self.__DFMlist) == 0:
            print("[INFO] No DFM found.")

class FieldEnum(object):
    def __init__(self, enumName: str, enumComment: str) -> None:
        self.__fieldEnumName = enumName
        self.__fieldEnumComment = enumComment
        self.__fieldEnumId = -1 #ida_idaapi.BADADDR
