from __future__ import annotations
import claripy

import bisa


class MessageBoxA(bisa.SimProcedure):
    def run(self, hWnd, lpText, lpCaption, uType):
        text = self.extract(lpText)
        caption = self.extract(lpCaption) if not self.state.solver.is_true(lpCaption == 0) else "Error"

        result = claripy.If(
            uType & 0xF == 0, 1, self.state.solver.BVS("messagebox_button", 32, key=("api", "messagebox", "button"))
        )
        self.state.history.add_event("message_box", text=text, caption=caption, result=result)
        return result

    def extract(self, addr):
        return self.state.mem[addr].string.concrete


class MessageBoxExA(MessageBoxA):
    def run(self, hWnd, lpText, lpCaption, uType, wLanguageId):
        super().run(hWnd, lpText, lpCaption, uType)


class MessageBoxW(MessageBoxA):
    def extract(self, addr):
        return self.state.mem[addr].wstring.concrete


class MessageBoxExW(MessageBoxW, MessageBoxExA):
    pass


class MessageBoxIndirectA(MessageBoxExA):
    def run(self, lpMsgBoxParams):
        if self.arch.bits != 32:
            raise bisa.errors.SimProcedureError("MessageBoxIndirectA is only implemented for 32 bit windows")
        hwndOwner = self.state.mem[lpMsgBoxParams + 0x4].dword.resolved
        lpszText = self.state.mem[lpMsgBoxParams + 0xC].dword.resolved
        lpszCaption = self.state.mem[lpMsgBoxParams + 0x10].dword.resolved
        dwStyle = self.state.mem[lpMsgBoxParams + 0x14].dword.resolved
        dwLanguageId = self.state.mem[lpMsgBoxParams + 0x24].dword.resolved
        super().run(hwndOwner, lpszText, lpszCaption, dwStyle, dwLanguageId)


class MessageBoxIndirectW(MessageBoxW, MessageBoxIndirectA):
    pass
