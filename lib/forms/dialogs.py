import idaapi


class FunctionRenameForm(idaapi.Form):
    def __init__(self):
        idaapi.Form.__init__(self, r"""New name of function
                                       <#Hint1#Name:{iSymbol}>""",
                             {'iSymbol': idaapi.Form.StringInput(tp=idaapi.Form.FT_ASCII)})


class CommentForm(idaapi.Form):
    def __init__(self):
        idaapi.Form.__init__(self, r"""Enter comment
                                           <#Hint1#Text:{iCommentText}>""",
                             {'iCommentText': idaapi.Form.StringInput(tp=idaapi.Form.FT_ASCII)})


class DefineFunctionForm(idaapi.Form):
    def __init__(self):
        idaapi.Form.__init__(self, r"""Define function
                                            <#Hint1#Enter Begin address of function:{iBAddr}>
                                            <#Hint1#Enter call handler address of function:{iHandlerAddr}>""",
                             {'iBAddr': idaapi.Form.NumericInput(tp=idaapi.Form.FT_ADDR),
                              'iHandlerAddr': idaapi.Form.NumericInput(tp=idaapi.Form.FT_ADDR)
                              })


class JumpByForm(idaapi.Form):
    def __init__(self):
        idaapi.Form.__init__(self, r"""Enter address
                                           <#Hint1#Address:{iJumpByAddr}>""",
                             {'iJumpByAddr': idaapi.Form.NumericInput(tp=idaapi.Form.FT_ADDR)})


class ToNativeForm(idaapi.Form):
    def __init__(self):
        idaapi.Form.__init__(self, r"""Enter address
                                       {FormChangeCb}
                                           <#Hint1#Choose addresses fixup file:{iFileOpen}>
                                           <Recursive mode:{rRecirsiveMode}>{cModeGroup1}>""",
                             {'iFileOpen': idaapi.Form.FileInput(open=True),
                              'cModeGroup1': idaapi.Form.ChkGroupControl(("rRecirsiveMode",)),
                              'FormChangeCb': idaapi.Form.FormChangeCb(self.OnFormChange)
                              })

    def OnFormChange(self, fid):
        if fid == self.rRecirsiveMode.id:
            self.rRecirsiveMode.checked = not self.rRecirsiveMode.checked
        return 1


