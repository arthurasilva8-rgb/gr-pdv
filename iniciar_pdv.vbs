Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

' Pega automaticamente o caminho da pasta onde o sistema está salvo
pastaSistema = fso.GetParentFolderName(WScript.ScriptFullName)
WshShell.CurrentDirectory = pastaSistema

' Roda usando o pythonw.exe do ambiente virtual (0 = totalmente oculto, sem tela preta)
comando = """" & pastaSistema & "\.venv\Scripts\pythonw.exe"" """ & pastaSistema & "\app.py"""
WshShell.Run comando, 0, False