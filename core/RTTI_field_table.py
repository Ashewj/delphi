from RTTI_delphi_custom import *
from RTTI_type_info import *
from typing import Optional

import pefile

class FieldTable(object):

    def __init__(
            self,
            pe: pefile.PE,
            classInfo: dict[str, str | dict[str, int]],
            fieldEnum: FieldEnum) -> None:
        self.__pe = pe
        self.__tableAddr = classInfo["Address"]["FieldTable"]
        self.__classInfo = classInfo
        self.__fieldEnum = fieldEnum
        self.__tableName = classInfo["Name"]
        self.__NoNameCounter = 1
        self.__processorWordSize = GetProcessorWordSize(self.__pe)
        self.__classTableEntries = list()

        if self.__tableAddr != 0:
            self.__classTableAddr = GetCustomWord(
                self.__pe, 
                self.__tableAddr + 2,
                self.__processorWordSize
            )

    def GetTableAddress(self) -> int:
        return self.__tableAddr

    def MakeTable(self) -> None:
        if self.__tableAddr != 0:
            self.__DeleteTable()
            self.__CreateTableAndExtractData()

    def __CreateExtendedTableAndExtractData(self, addr: int) -> None:
        MakeWord(self.__pe, addr)
        numOfEntries = Word(self.__pe, addr)
        MakeName(addr, self.__tableName + "_ExtendedFieldTable")
        #ida_bytes.set_cmt(addr, "Number of records", 0)

        addr += 2

        for i in range(numOfEntries):
            nameAddr = addr + 5 + self.__processorWordSize
            recordSize = (8 + self.__processorWordSize
                          + Byte(self.__pe, nameAddr)
                          + Word(self.__pe, addr + 6
                                 + self.__processorWordSize
                                 + Byte(self.__pe, nameAddr))
                          - 2)

            MakeByte(self.__pe, addr)

            MakeCustomWord(self.__pe, addr + 1, self.__processorWordSize)
            typeInfoAddr = GetCustomWord(self.__pe, addr + 1, self.__processorWordSize)
            typeName = self.__ExtractTypeName(typeInfoAddr)

            if typeName is not None:
                MakeDword(self.__pe, addr + 1 + self.__processorWordSize)
                offset = Dword(self.__pe, addr + 1 + self.__processorWordSize)

                if Byte(self.__pe, nameAddr) != 0:
                    MakeStr_PASCAL(self.__pe, nameAddr)
                    name = GetStr_PASCAL(self.__pe, nameAddr)
                else:
                    MakeByte(self.__pe, nameAddr)
                    name = "NoName" + str(self.__NoNameCounter)
                    self.__NoNameCounter += 1

                MakeWord(self.__pe, addr + 6
                         + self.__processorWordSize
                         + Byte(self.__pe, nameAddr))

                if name[0] == "F":
                    tempName = name[1:]
                else:
                    tempName = name

                #self.__fieldEnum.AddMember(typeName, tempName, offset)
                addr = addr + recordSize
            else:
                return

    def __CreateTableAndExtractData(self) -> None:
        MakeWord(self.__pe, self.__tableAddr)
        MakeName(self.__tableAddr, self.__tableName + "_FieldTable")

        """ida_bytes.set_cmt(
            self.__tableAddr,
            "Number of records",
            0
        )"""

        MakeCustomWord(self.__pe, self.__tableAddr + 2, self.__processorWordSize)

        """ida_bytes.set_cmt(
            self.__tableAddr + 2,
            "Class table",
            0
        )"""

        #classTable = ClassTable(self.__classTableAddr, self.__tableName)
        #self.__classTableEntries = classTable.MakeTable()

        addr = self.__tableAddr + 2 + self.__processorWordSize
        numOfEntries = Word(self.__pe, self.__tableAddr)

        for i in range(numOfEntries):
            fieldClassInfo = None
            recordSize = 7 + Byte(self.__pe, addr + 6)

            MakeDword(self.__pe, addr)
            offset = Dword(self.__pe, addr)
            MakeWord(self.__pe, addr + 4)
            index = Word(self.__pe, addr + 4)

            if Byte(self.__pe, addr + 6) != 0:
                MakeStr_PASCAL(self.__pe, addr + 6)
                name = GetStr_PASCAL(self.__pe, addr + 6)
            else:
                MakeByte(self.__pe, addr + 6)
                name = "NoName" + str(self.__NoNameCounter)
                self.__NoNameCounter += 1

            """if is_loaded(self.__classTableEntries[index]) and \
               self.__classTableEntries[index] != 0:
                from DelphiHelper.core.DelphiClass import DelphiClass
                delphiClass = DelphiClass(self.__classTableEntries[index])
                fieldClassInfo = delphiClass.GetClassInfo()

                ida_bytes.set_cmt(
                    addr,
                    fieldClassInfo["FullName"],
                    0
                )"""

            MakeName(addr, self.__tableName + "_" + name)

            if name[0] == "F":
                tempName = name[1:]
            else:
                tempName = name

            """if fieldClassInfo is None:
                self.__fieldEnum.AddMember(
                    "Unknown",
                    tempName,
                    offset
                )
            else:
                self.__fieldEnum.AddMember(
                    fieldClassInfo["Name"],
                    tempName,
                    offset
                )"""

            addr = addr + recordSize

        methodTableAddr = self.__classInfo["Address"]["MethodTable"]
        dynamicTableAddr = self.__classInfo["Address"]["DynamicTable"]
        classNameAddr = self.__classInfo["Address"]["ClassName"]

        if (methodTableAddr != 0 and addr < methodTableAddr) or \
           (methodTableAddr == 0 and dynamicTableAddr != 0 and addr < dynamicTableAddr) or \
           (methodTableAddr == 0 and dynamicTableAddr == 0 and addr < classNameAddr):
            self.__CreateExtendedTableAndExtractData(addr)

    def __DeleteTable(self) -> None:
        """ida_bytes.del_items(
            self.__tableAddr,
            ida_bytes.DELIT_DELNAMES,
            2 + self.__processorWordSize
        )"""

        addr = self.__tableAddr + 2 + self.__processorWordSize
        numOfEntries = Word(self.__pe, self.__tableAddr)

        for i in range(numOfEntries):
            recordSize = 7 + Byte(self.__pe, addr + 6)
            #ida_bytes.del_items(addr, ida_bytes.DELIT_DELNAMES, recordSize)
            addr = addr + recordSize

        methodTableAddr = self.__classInfo["Address"]["MethodTable"]
        dynamicTableAddr = self.__classInfo["Address"]["DynamicTable"]
        classNameAddr = self.__classInfo["Address"]["ClassName"]

        if (methodTableAddr != 0 and addr < methodTableAddr) or \
           (methodTableAddr == 0 and dynamicTableAddr != 0 and addr < dynamicTableAddr) or \
           (methodTableAddr == 0 and dynamicTableAddr == 0 and addr < classNameAddr):
            #ida_bytes.del_items(addr, ida_bytes.DELIT_DELNAMES, 2)
            numOfEntries = Word(self.__pe, addr)
            addr += 2

            for i in range(numOfEntries):
                recordSize = (8 + self.__processorWordSize
                              + Byte(self.__pe, addr + 5 + self.__processorWordSize)
                              + Word(self.__pe, addr + 6 + self.__processorWordSize + Byte(self.__pe, addr + 5 + self.__processorWordSize))
                              - 2)

                """ida_bytes.del_items(
                    addr,
                    ida_bytes.DELIT_DELNAMES,
                    recordSize
                )"""

                addr = addr + recordSize

    def __ExtractTypeName(self, addr: int) -> Optional[str]:
        typeName = None

        if addr == 0:
            typeName = "NoType"
        elif is_loaded(self.__pe, addr):
            typeInfo = TypeInfo(self.__pe, addr + self.__processorWordSize)
            typeInfo.MakeTable(1)
            typeName = typeInfo.GetTypeName()
        elif get_segm_name(self.__pe, addr) == ".idata": #get_name(addr).startswith("@") and 
            typeName = get_name(addr)
            typeName = typeName.split('@')[-1]
            typeName = typeName.split('$')[-1]
            typeName = "".join([i for i in typeName if not i.isdigit()])

            if not len(typeName):
                typeName = None

        return typeName
