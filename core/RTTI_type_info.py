from RTTI_delphi_custom import *
import pefile

class TypeInfo(object):
    typeKindList = ["tkUnknown", "tkInteger", "tkChar", "tkEnumeration",
                    "tkFloat", "tkString", "tkSet", "tkClass", "tkMethod",
                    "tkWChar", "tkLString", "tkLWString", "tkVariant",
                    "tkArray", "tkRecord", "tkInterface", "tkInt64",
                    "tkDynArray", "tkUString", "tkClassRef", "tkPointer",
                    "tkProcedure", "tkMRecord"]

    def __init__(
            self,
            pe,
            addr: int,
            fieldEnum: FieldEnum = None) -> None:
        self.__pe = pe
        self.__fieldEnum = fieldEnum
        self.__tableAddr = addr
        self.__processorWordSize = GetProcessorWordSize(self.__pe)

        if self.__tableAddr != 0:
            self.__typeName = GetStr_PASCAL(self.__pe, self.__tableAddr + 1)
            if self.__typeName is None:
                msg = ("TypeInfo: TypeName is None ("
                       + hex(self.__tableAddr)
                       + ").")
                raise Exception(msg)

            self.__typeKind = Byte(self.__pe, self.__tableAddr)
            if self.__typeKind >= len(self.typeKindList):
                msg = ("TypeInfo: TypeKind out of range - "
                       + str(self.__typeKind)
                       + " ("
                       + hex(self.__tableAddr)
                       + ").")
                raise Exception(msg)

            self.__typeDataAddr = self.__tableAddr + 2 + Byte(self.__pe, self.__tableAddr + 1)
            self.__propDataAddr = (self.__typeDataAddr
                                   + 2 * self.__processorWordSize
                                   + 3
                                   + Byte(self.__pe, self.__typeDataAddr + 2 * self.__processorWordSize + 2))

    def GetTableAddress(self) -> int:
        return self.__tableAddr

    def GetTypeName(self) -> str:
        return self.__typeName

    def MakeTable(self, resolveTypeInfoClass: int = 0) -> None:
        if is_loaded(self.__pe, self.__tableAddr) and \
           self.__tableAddr != 0 and \
           "_TypeInfo" not in get_name(self.__tableAddr):
            if resolveTypeInfoClass != 0:
                self.__ResolveTypeInfo(self.__tableAddr)
            else:
                self.__DeleteTable()
                self.__CreateTable()
                self.__ExtractData()

    def __ResolveTypeInfo(self, tableAddr: int) -> None:
        typeKind = Byte(self.__pe, tableAddr)

        if typeKind != 0xff:
            if self.typeKindList[typeKind] == "tkClass":
                if self.__processorWordSize == 4:
                    ref = FindRef_Dword(
                        self.__pe,
                        tableAddr - 4,
                        tableAddr,
                        False
                    )
                else:
                    ref = FindRef_Qword(
                        self.__pe,
                        tableAddr - 4,
                        tableAddr,
                        False
                    )

                if ref != -1:
                    classAddr = ref - 4 * self.__processorWordSize
                    className = get_name(classAddr)

                    if not className.startswith("VMT_"):
                        from DelphiData import DelphiClass
                        DelphiClass(self.__pe, classAddr).MakeClass()
            else:
                TypeInfo(self.__pe, tableAddr).MakeTable()

    def __CreatePropDataRecord_Class(self, addr: int) -> None:
        nameAddr = addr + 4 * self.__processorWordSize + 10
        recordSize = 4 * self.__processorWordSize + 11 + Byte(nameAddr)
        nextRecordAddr = addr + recordSize

        typeInfoAddr = GetCustomWord(self.__pe, addr, self.__processorWordSize)
        if is_loaded(self.__pe, typeInfoAddr) and \
           typeInfoAddr != 0 and \
           "_TypeInfo" not in get_name(typeInfoAddr):
            self.__ResolveTypeInfo(typeInfoAddr + self.__processorWordSize)

        MakeCustomWord(self.__pe, addr, self.__processorWordSize)
        #ida_bytes.set_cmt(addr, "PropType", 0)

        addr += self.__processorWordSize
        MakeCustomWord(self.__pe, addr, self.__processorWordSize)
        #ida_bytes.set_cmt(addr, "GetProc", 0)

        shiftCount = (self.__processorWordSize - 1) * 8
        bitmask = GetCustomWord(self.__pe, addr, self.__processorWordSize) >> shiftCount
        if bitmask & 0xC0 == 0:
            MakeName(
                GetCustomWord(self.__pe, addr, self.__processorWordSize),
                self.__typeName + "_Get" + GetStr_PASCAL(self.__pe, nameAddr)
            )

        addr += self.__processorWordSize
        MakeCustomWord(self.__pe, addr, self.__processorWordSize)
        #ida_bytes.set_cmt(addr, "SetProc", 0)

        bitmask = GetCustomWord(self.__pe, addr, self.__processorWordSize) >> shiftCount
        if bitmask & 0xC0 == 0:
            MakeName(
                GetCustomWord(self.__pe, addr, self.__processorWordSize),
                self.__typeName + "_Set" + GetStr_PASCAL(self.__pe, nameAddr)
            )

        addr += self.__processorWordSize
        MakeCustomWord(self.__pe, addr, self.__processorWordSize)
        #ida_bytes.set_cmt(addr, "StoredProc", 0)

        addr += self.__processorWordSize
        MakeDword(self.__pe, addr)
        #ida_bytes.set_cmt(addr, "Index", 0)

        addr += 4
        MakeDword(self.__pe, addr)
        #ida_bytes.set_cmt(addr, "Default", 0)

        addr += 4
        MakeWord(self.__pe, addr)
        #ida_bytes.set_cmt(addr, "NameIndex", 0)

        MakeStr_PASCAL(self.__pe, nameAddr)
        #ida_bytes.set_cmt(nameAddr, "Name", 0)

        MakeName(
            nextRecordAddr - recordSize,
            self.__typeName + "_" + GetStr_PASCAL(self.__pe, nameAddr)
        )

        return nextRecordAddr

    def __CreateTypeData_Class(self) -> None:
        addr = self.__typeDataAddr

        MakeCustomWord(self.__pe, addr, self.__processorWordSize)
        #ida_bytes.set_cmt(addr, "TypeData.ClassType", 0)

        addr += self.__processorWordSize
        MakeCustomWord(self.__pe, addr, self.__processorWordSize)
        #ida_bytes.set_cmt(addr, "TypeData.ParentInfo", 0)

        typeInfoAddr = GetCustomWord(self.__pe, addr, self.__processorWordSize)
        if is_loaded(typeInfoAddr) and \
           typeInfoAddr != 0 and \
           "_TypeInfo" not in get_name(typeInfoAddr):
            self.__ResolveTypeInfo(typeInfoAddr + self.__processorWordSize)

        addr += self.__processorWordSize
        MakeWord(self.__pe, addr)
        #ida_bytes.set_cmt(addr, "TypeData.PropCount", 0)

        addr += 2
        MakeStr_PASCAL(self.__pe, addr)
        #da_bytes.set_cmt(addr, "TypeData.UnitName", 0)

        MakeWord(self.__pe, self.__propDataAddr)
        #ida_bytes.set_cmt(self.__propDataAddr, "TypeData.PropData.PropCount", 0)

        propCount = Word(self.__pe, self.__propDataAddr)
        addr = self.__propDataAddr + 2

        for i in range(propCount):
            addr = self.__CreatePropDataRecord_Class(addr)

        propCount = Word(self.__pe, addr)

        if propCount != 0 and propCount <= 0xff:
            if (Byte(self.__pe, addr + 2) == 2) or (Byte(self.__pe, addr + 2) == 3):
                MakeWord(self.__pe, addr)
                addr += 2

                for i in range(propCount):
                    MakeByte(self.__pe, addr)
                    MakeCustomWord(self.__pe, addr + 1, self.__processorWordSize)

                    nameAddr = GetCustomWord(self.__pe, addr + 1, self.__processorWordSize)
                    name = get_name(nameAddr)
                    if self.__typeName not in name:
                        propDataRecordAddr = GetCustomWord(
                            self.__pe, 
                            addr + 1,
                            self.__processorWordSize
                        )
                        self.__CreatePropDataRecord_Class(propDataRecordAddr)

                    MakeWord(self.__pe, addr + 1 + self.__processorWordSize)
                    addr += (1 + self.__processorWordSize
                             + Word(self.__pe, addr + 1 + self.__processorWordSize))

    def __CreateTableHeader(self) -> None:
        MakeByte(self.__pe, self.__tableAddr)

        """if self.__typeKind < len(self.typeKindList):
            ida_bytes.set_cmt(
                self.__tableAddr,
                "Type kind - " + self.typeKindList[self.__typeKind],
                0
            )
        else:
            ida_bytes.set_cmt(
                self.__tableAddr,
                "Type kind - UNKNOWN",
                0
            )"""

        MakeStr_PASCAL(self.__pe, self.__tableAddr + 1)
        #ida_bytes.set_cmt(self.__tableAddr + 1, "Type name", 0)

        MakeName(self.__tableAddr, self.__typeName + "_TypeInfo")

        addr = GetCustomWord(
            self.__pe, 
            self.__tableAddr - self.__processorWordSize,
            self.__processorWordSize
        )

        if addr == self.__tableAddr:
            MakeCustomWord(
                self.__pe, 
                self.__tableAddr - self.__processorWordSize,
                self.__processorWordSize
            )
            
            MakeName(
                self.__tableAddr - self.__processorWordSize,
                "_" + self.__typeName + "_TypeInfo"
            )

    def __CreateTable(self) -> None:
        self.__CreateTableHeader()

        if self.typeKindList[self.__typeKind] == "tkClass":
            self.__CreateTypeData_Class()

    def __DeletePropDataRecord_Class(self, addr: int) -> int:
        recordSize = (4 * self.__processorWordSize
                      + 11
                      + Byte(self.__pe, addr + 4 * self.__processorWordSize + 10))
        #ida_bytes.del_items(addr, ida_bytes.DELIT_DELNAMES, recordSize)
        return addr + recordSize

    def __DeleteTypeData_Class(self) -> None:
        size = (2 * self.__processorWordSize
                + 5
                + Byte(self.__pe, self.__typeDataAddr + 2 * self.__processorWordSize + 2))

        """ida_bytes.del_items(
            self.__typeDataAddr,
            ida_bytes.DELIT_DELNAMES,
            size
        )"""

        propCount = Word(self.__pe, self.__propDataAddr)
        addr = self.__propDataAddr + 2

        for i in range(propCount):
            addr = self.__DeletePropDataRecord_Class(addr)

        propCount = Word(self.__pe, addr)

        if propCount != 0:
            if Byte(self.__pe, addr + 2) == 2 or Byte(self.__pe, addr + 2) == 3:
                #ida_bytes.del_items(addr, ida_bytes.DELIT_DELNAMES, 2)
                addr += 2

                for i in range(propCount):
                    """ida_bytes.del_items(
                        addr,
                        ida_bytes.DELIT_DELNAMES,
                        3 + self.__processorWordSize
                    )"""

                    propDataRecordAddr = GetCustomWord(
                        self.__pe, 
                        addr + 1,
                        self.__processorWordSize
                    )
                    self.__DeletePropDataRecord_Class(propDataRecordAddr)

                    addr += (self.__processorWordSize
                             + 1
                             + Word(self.__pe, addr + self.__processorWordSize + 1))

    def __DeleteTableHeader(self) -> None:
        """ida_bytes.del_items(
            self.__tableAddr,
            ida_bytes.DELIT_DELNAMES,
            1
        )
        ida_bytes.del_items(
            self.__tableAddr + 1,
            ida_bytes.DELIT_DELNAMES,
            1 + Byte(self.__tableAddr + 1)
        )"""

        addr = GetCustomWord(
            self.__pe, 
            self.__tableAddr - self.__processorWordSize,
            self.__processorWordSize
        )

        """if addr == self.__tableAddr:
            ida_bytes.del_items(
                self.__tableAddr - self.__processorWordSize,
                ida_bytes.DELIT_DELNAMES,
                self.__processorWordSize
            )"""

    def __DeleteTable(self) -> None:
        self.__DeleteTableHeader()

        if self.typeKindList[self.__typeKind] == "tkClass":
            self.__DeleteTypeData_Class()

    def __ExtractData_PropDataRecord_Class(self, addr: int) -> int:
        nameAddr = addr + 4 * self.__processorWordSize + 10
        getProcEntry = GetCustomWord(
            self.__pe, 
            addr + self.__processorWordSize,
            self.__processorWordSize
        )
        setProcEntry = GetCustomWord(
            self.__pe, 
            addr + 2 * self.__processorWordSize,
            self.__processorWordSize
        )
        recordSize = 4 * self.__processorWordSize + 11 + Byte(nameAddr)
        shiftVal = (self.__processorWordSize - 1) * 8

        if self.__processorWordSize == 4:
            mask1 = 0x00FFFFFF
        else:
            mask1 = 0x00FFFFFFFFFFFFFF

        typeInfoAddr = GetCustomWord(addr, self.__processorWordSize)

        if is_loaded(self.__pe, typeInfoAddr) and typeInfoAddr != 0:
            typeInfo = TypeInfo(typeInfoAddr + self.__processorWordSize)
            typeName = typeInfo.GetTypeName()

            if ((getProcEntry >> shiftVal) & 0xF0 != 0) and \
               ((setProcEntry >> shiftVal) & 0xF0 != 0):
                if getProcEntry == setProcEntry:
                    self.__fieldEnum.AddMember(
                        typeName,
                        GetStr_PASCAL(self.__pe, nameAddr),
                        setProcEntry & mask1
                    )
                else:
                    self.__fieldEnum.AddMember(
                        typeName,
                        GetStr_PASCAL(self.__pe, nameAddr) + "_Get",
                        getProcEntry & mask1
                    )
                    self.__fieldEnum.AddMember(
                        typeName,
                        GetStr_PASCAL(self.__pe, nameAddr) + "_Set",
                        setProcEntry & mask1
                    )
            else:
                if (getProcEntry >> shiftVal) & 0xF0 != 0:
                    self.__fieldEnum.AddMember(
                        typeName,
                        GetStr_PASCAL(self.__pe, nameAddr),
                        getProcEntry & mask1
                    )
                if (setProcEntry >> shiftVal) & 0xF0 != 0:
                    self.__fieldEnum.AddMember(
                        typeName,
                        GetStr_PASCAL(self.__pe, nameAddr),
                        setProcEntry & mask1
                    )

        return addr + recordSize

    def __ExtractData_TypeData_Class(self) -> None:
        propCount = Word(self.__pe, self.__propDataAddr)
        addr = self.__propDataAddr + 2

        for i in range(propCount):
            addr = self.__ExtractData_PropDataRecord_Class(addr)

        propCount = Word(self.__pe, addr)

        if propCount != 0 and \
           propCount <= 0xff and \
           (Byte(self.__pe, addr + 2) == 2 or Byte(self.__pe, addr + 2) == 3):
            addr += 2

            for i in range(propCount):
                propDataRecordAddr = GetCustomWord(
                    self.__pe, 
                    addr + 1,
                    self.__processorWordSize
                )
                self.__ExtractData_PropDataRecord_Class(propDataRecordAddr)

                addr += (self.__processorWordSize
                         + 1
                         + Word(self.__pe, addr + self.__processorWordSize + 1))

    def __ExtractData(self) -> None:
        if self.typeKindList[self.__typeKind] == "tkClass" and \
           self.__fieldEnum is not None:
            self.__ExtractData_TypeData_Class()
