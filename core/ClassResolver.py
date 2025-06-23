from RTTI_delphi_custom import *
from DelphiData import *

def ResolveApplicationClass(pe: pefile.PE, classAddr: int = -1) -> None:
    if classAddr == -1:
        classAddr = GetApplicationClassAddr(pe)
        if classAddr == -1:
            return

    classApplicationName = get_name(classAddr)

    if not classApplicationName.startswith('VMT_'):
        #ida_kernwin.show_wait_box("NODELAY\nHIDECANCEL\nProcessing \"TApplication\" VMT structure...")
        try:
            DelphiClass(pe, classAddr).MakeClass()
        except Exception as e:
            print(f'[ERROR] | {e}')
            pass
        #finally:
            #ida_kernwin.hide_wait_box()


#def ResolveClass(classAddr: int) -> None:
#    ResolveApplicationClass()
#    DelphiClass(classAddr).MakeClass()
