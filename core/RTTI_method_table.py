from RTTI_delphi_custom import *
from RTTI_type_info import *
import pefile

class MethodTable(object):

    def __init__(self, pe: pefile.PE, classInfo: dict[str, str | dict[str, int]]) -> None:
        self.__pe = pe
        self.__tableAddr = classInfo["Address"]["MethodTable"]
        self.__tableName = classInfo["Name"]
        self.__classInfo = classInfo
        self.__processorWordSize = GetProcessorWordSize(self.__pe)

    def GetTableAddress(self) -> int:
        return self.__tableAddr

    def MakeTable(self) -> None:
        if self.__tableAddr != 0:
            self.__DeleteTable()
            self.__CreateTable()

    def GetMethods(self) -> list[tuple[str, int]]:
        methodList = list()
        if self.__tableAddr != 0:
            numOfEntries = Word(self.__pe, self.__tableAddr)
            addr = self.__tableAddr + 2
            for i in range(numOfEntries):
                methodAddr = GetCustomWord(self.__pe, addr + 2, self.__processorWordSize)
                methodName = GetStr_PASCAL(self.__pe, addr + 2 + self.__processorWordSize)
                addr += Word(self.__pe, addr)
                methodList.append((methodName, methodAddr))
        return methodList

    def __CreateTable(self) -> None:
        MakeWord(self.__pe, self.__tableAddr)
        MakeName(self.__tableAddr, self.__tableName + "_MethodTable")

        """ida_bytes.set_cmt(
            self.__tableAddr,
            "Number of records",
            0
        )"""

        numOfEntries = Word(self.__pe, self.__tableAddr)
        """if numOfEntries != 0:
            ida_bytes.set_cmt(
                self.__tableAddr + 2,
                "Record size",
                0
            )
            ida_bytes.set_cmt(
                self.__tableAddr + 4,
                "Method pointer",
                0
            )
            ida_bytes.set_cmt(
                self.__tableAddr + 4 + self.__processorWordSize,
                "Method Name",
                0
            )"""

        addr = self.__tableAddr + 2
        for i in range(numOfEntries):
            recordSize = Word(self.__pe, addr)

            MakeWord(self.__pe, addr)
            #print(f'TODO: ')
            #MakeFunction(GetCustomWord(self.__pe, addr + 2, self.__processorWordSize))
            MakeCustomWord(self.__pe, addr + 2, self.__processorWordSize)
            MakeStr_PASCAL(self.__pe, addr + 2 + self.__processorWordSize)

            name = (self.__tableName
                    + "_"
                    + GetStr_PASCAL(self.__pe, addr + 2 + self.__processorWordSize))

            
            MakeName(
                GetCustomWord(self.__pe, addr + 2, self.__processorWordSize),
                name
            )

            addr = addr + recordSize

        dynamicTableAddr = self.__classInfo["Address"]["DynamicTable"]
        classNameAddr = self.__classInfo["Address"]["ClassName"]

        if (dynamicTableAddr == 0 and addr < classNameAddr) or \
           (dynamicTableAddr != 0 and addr < dynamicTableAddr):
            numOfEntries = Word(self.__pe, addr)
            MakeWord(self.__pe, addr)
            addr += 2
            
            #print(numOfEntries)
            for i in range(numOfEntries):
                MakeCustomWord(self.__pe, addr, self.__processorWordSize)
                MakeByte(self.__pe, addr + self.__processorWordSize)
                #idc.make_array(addr + self.__processorWordSize, 4)

                recordAddr = GetCustomWord(self.__pe, addr, self.__processorWordSize)
                self.__CreateFunctionRecord(recordAddr)
                addr += 4 + self.__processorWordSize

    def __CreateFunctionRecord(self, addr: int) -> None:
        recordSize = Word(self.__pe, addr)
        funcNameAddr = addr + 2

        MakeWord(self.__pe, addr)

        nameAddr = GetCustomWord(self.__pe, funcNameAddr, self.__processorWordSize)
        name = get_name(nameAddr)
        #if self.__tableName not in name:
            #print(f'TODO: ')
            #MakeFunction(GetCustomWord(self.__pe, funcNameAddr, self.__processorWordSize))

        MakeCustomWord(self.__pe, funcNameAddr, self.__processorWordSize)
        MakeStr_PASCAL(self.__pe, funcNameAddr + self.__processorWordSize)
        funcBaseName = GetStr_PASCAL(self.__pe, funcNameAddr + self.__processorWordSize)

        MakeName(addr, "_" + self.__tableName + "_" + funcBaseName)

        funcPrototype = ("void __usercall "
                         + self.__tableName
                         + "_"
                         + funcBaseName
                         + "(")

        size = (3 + self.__processorWordSize
                + Byte(self.__pe, funcNameAddr + self.__processorWordSize))

        if recordSize > size:
            addr += size
            MakeCustomWord(self.__pe, addr, self.__processorWordSize)
            addr += self.__processorWordSize
            MakeDword(self.__pe, addr)
            addr += 4
            MakeByte(self.__pe, addr)

            numOfParams = Byte(self.__pe, addr)
            addr += 1

            if funcBaseName == "Create":
                numOfParams += 1

            for i in range(numOfParams):
                regStr = str()

                if self.__processorWordSize == 4:
                    if i == 0:
                        regStr = "@<eax>"
                    elif i == 1:
                        regStr = "@<edx>"
                    elif i == 2:
                        regStr = "@<ecx>"
                else:
                    if i == 0:
                        regStr = "@<rcx>"
                    elif i == 1:
                        regStr = "@<rdx>"
                    elif i == 2:
                        regStr = "@<r8>"
                    elif i == 3:
                        regStr = "@<r9>"

                if i == 1 and funcBaseName == "Create":
                    funcPrototype += "void* ShortInt_Alloc" + regStr
                else:
                    MakeByte(self.__pe, addr)
                    MakeCustomWord(self.__pe, addr + 1, self.__processorWordSize)
                    MakeWord(self.__pe, addr + 1 + self.__processorWordSize)
                    MakeStr_PASCAL(self.__pe, addr + 3 + self.__processorWordSize)

                    wordAddr = (addr + 4
                                + self.__processorWordSize
                                + Byte(self.__pe, addr + 3 + self.__processorWordSize))
                    MakeWord(self.__pe, wordAddr)

                    argTypeInfo = GetCustomWord(self.__pe, 
                        addr + 1,
                        self.__processorWordSize
                    )

                    if argTypeInfo == 0:
                        typeName = "NoType"
                    elif is_mapped(self.__pe, argTypeInfo) and is_loaded(self.__pe, argTypeInfo):
                        typeInfoAddr = argTypeInfo + self.__processorWordSize
                        typeInfo = TypeInfo(self.__pe, typeInfoAddr)
                        typeInfo.MakeTable(1)
                        typeName = typeInfo.GetTypeName()
                    else:
                        return

                    paramNameAddr = addr + 3 + self.__processorWordSize
                    paramName = GetStr_PASCAL(self.__pe, paramNameAddr)
                    if paramName is None:
                        paramName = "RetVal"

                    funcPrototype += ("void* "
                                      + typeName
                                      + "_"
                                      + paramName
                                      + regStr)

                    addr = (addr + 6
                            + self.__processorWordSize
                            + Byte(self.__pe, addr + 3 + self.__processorWordSize))

                if i != numOfParams - 1:
                    funcPrototype += ", "

            MakeWord(self.__pe, addr)

        funcPrototype += ");"

        nameAddr = GetCustomWord(self.__pe, funcNameAddr, self.__processorWordSize)
        name = get_name(nameAddr)

        if self.__tableName not in name:
            MakeName(
                GetCustomWord(self.__pe, funcNameAddr, self.__processorWordSize),
                self.__tableName + "_" + funcBaseName
            )

        """idc.SetType(
            GetCustomWord(self.__pe, funcNameAddr, self.__processorWordSize),
            funcPrototype
        )"""

    def __DeleteTable(self) -> None:
        #ida_bytes.del_items(self.__tableAddr, ida_bytes.DELIT_DELNAMES, 2)

        addr = self.__tableAddr + 2
        numOfEntries = Word(self.__pe, self.__tableAddr)

        for i in range(numOfEntries):
            recordSize = Word(self.__pe, addr)
            #ida_bytes.del_items(addr, ida_bytes.DELIT_DELNAMES, recordSize)
            addr = addr + recordSize

        dynamicTableAddr = self.__classInfo["Address"]["DynamicTable"]
        classNameAddr = self.__classInfo["Address"]["ClassName"]

        if (dynamicTableAddr == 0 and addr < classNameAddr) or \
           (dynamicTableAddr != 0 and addr < dynamicTableAddr):
            numOfEntries = Word(self.__pe, addr)
            #ida_bytes.del_items(addr, ida_bytes.DELIT_DELNAMES, 2)
            addr += 2

            for i in range(numOfEntries):
                """ida_bytes.del_items(
                    addr,
                    ida_bytes.DELIT_DELNAMES,
                    4 + self.__processorWordSize
                )
                ida_bytes.del_items(
                    GetCustomWord(self.__pe, addr, self.__processorWordSize),
                    ida_bytes.DELIT_DELNAMES,
                    Word(self.__pe, GetCustomWord(self.__pe, addr, self.__processorWordSize))
                )"""
                addr += 4 + self.__processorWordSize
