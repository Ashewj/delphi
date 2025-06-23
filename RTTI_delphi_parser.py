from core.RTTI_delphi_custom import *
from core.DelphiData import *
from core.ClassResolver import *

import traceback

pe = pefile.PE(get_process_path_by_name("Project1.exe"))
ResolveApplicationClass(pe)

dfmList = DFMFinder(pe).GetDFMList()
numOfDfms = len(dfmList)
delphiFormList = list()

for i, dfmEntry in enumerate(dfmList):    
    data = get_bytes(pe, dfmEntry[0], dfmEntry[1])
    if data and (is_loaded(pe, dfmEntry[0] + dfmEntry[1] - 1) or dfmEntry[1] == 10000000):
        dfmEntryParser = DFMParser(data, dfmEntry[1])
        if dfmEntryParser.CheckSignature():
            methodList = list()
            VMTAddr = 0
            delphiDFM = dfmEntryParser.ParseForm()

            try:
                delphiRTTI = DelphiClass(pe, 0, delphiDFM.GetClassName())
                
                VMTAddr = delphiRTTI.GetVMTAddress()
                if not get_name(VMTAddr).startswith("VMT_"):
                    delphiRTTI.MakeClass()
                
                methodList = delphiRTTI.GetMethods()
            except Exception as e:
                print(f"[WARNING] | {type(e).__name__}: {e}")
                traceback.print_exc()

            delphiFormList.append((delphiDFM, methodList, VMTAddr))

        del dfmEntryParser

for addr, name in sorted(named_addresses.items()):
    print(f"0x{addr:06X} -> {name}")

#for delphiDFM, methodList, VMTAddr in delphiFormList:
#    print(methodList)