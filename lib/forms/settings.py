import idaapi


class SettingForm(idaapi.Form):
    def __init__(self, version):
        idaapi.Form.__init__(self, r"""FinSpy VM disassembler %s
                                        {FormChangeCb}
                                       <#Hint1#Enter EP ID:{iEpAddr}> 
                                       <#Hint2#Enter DecryptKey:{iDecryptKey}>
                                       <#Hint2#Enter VM Interpreter base:{iVMInterpreter}>
                                       <#Hint3#Choose VM trace file:{iFileOpen}>
                                       <Enable x64 mode:{rMode}>
                                       <Enable real registers mode:{rRealRegMode}>
                                       <Show opcode data:{rShowOpcodeData}>
                                       <Show ID instruction:{rShowIdInstruction}>{cModeGroup1}>""" % version,
                             {'iEpAddr': idaapi.Form.NumericInput(tp=idaapi.Form.FT_ADDR),
                              'iDecryptKey': idaapi.Form.NumericInput(tp=idaapi.Form.FT_ADDR),
                              'iVMInterpreter': idaapi.Form.NumericInput(tp=idaapi.Form.FT_ADDR),
                              'iFileOpen': idaapi.Form.FileInput(open=True),
                              'cModeGroup1': idaapi.Form.ChkGroupControl(("rMode", "rRealRegMode", "rShowOpcodeData",
                                                                          "rShowIdInstruction")),
                              'FormChangeCb': idaapi.Form.FormChangeCb(self.OnFormChange)
                              })

    def OnFormChange(self, fid):
        if fid == self.rMode.id:
            self.rMode.checked = not self.rMode.checked
        elif fid == self.rShowOpcodeData.id:
            self.rShowOpcodeData.checked = not self.rShowOpcodeData.checked
        elif fid == self.rShowIdInstruction.id:
            self.rShowIdInstruction.checked = not self.rShowIdInstruction.checked
        elif fid == self.rRealRegMode.id:
            self.rRealRegMode.checked = not self.rRealRegMode.checked
        return 1