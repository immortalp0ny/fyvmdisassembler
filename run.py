import idaapi

idaapi.require("lib.forms.settings")
idaapi.require("lib.view")

from lib.forms.settings import SettingForm
from lib.view import __d_version__, DisassemblerView


def main():
    f = SettingForm(__d_version__)
    f.Compile()
    ok = f.Execute()
    if ok:
        if not f.iFileOpen.value or not f.iEpAddr.value or not f.iDecryptKey.value or not f.iVMInterpreter:
            print "[~] Error. All params must be set"
            return

        view = DisassemblerView()
        mode = 64 if f.rMode.checked else 32
        is_virtual_reg = False if f.rRealRegMode.checked else True

        if not view.Create(f.iFileOpen.value, f.iEpAddr.value, f.iDecryptKey.value, f.iVMInterpreter.value, mode=mode,
                           show_opcode=f.rShowOpcodeData.checked, show_id=f.rShowIdInstruction.checked,
                           is_virtual_reg=is_virtual_reg):
            print "[~] Error create Disasm view"
            return
        view.Show()

if __name__ == '__main__':
    main()