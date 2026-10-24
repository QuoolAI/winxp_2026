Option Explicit
Dim shell, fso, key, value, errorCode, file, backup, restore
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
key = "HKCU\Software\Microsoft\Windows\ShellNoRoam\MUICache\@explorer.exe,-7021"
backup = "C:\xp25\branding-menu-cache-original.txt"
restore = False
If WScript.Arguments.Count > 0 Then restore = (WScript.Arguments(0) = "--restore")
If restore Then
  Set file = fso.OpenTextFile(backup, 1)
  value = file.ReadLine
  file.Close
  If value <> "&Help and Support" And value <> "XP25 &Help" Then WScript.Quit 3
  shell.RegWrite key, value, "REG_SZ"
  WScript.Quit 0
End If
On Error Resume Next
value = shell.RegRead(key)
errorCode = Err.Number
On Error GoTo 0
If errorCode = -2147024894 Then WScript.Quit 0
If errorCode <> 0 Then WScript.Quit 2
If value <> "&Help and Support" And value <> "XP25 &Help" Then WScript.Quit 3
If Not fso.FileExists(backup) Then
  Set file = fso.CreateTextFile(backup, False)
  file.WriteLine value
  file.Close
End If
shell.RegDelete key
WScript.Echo "Removed only the Start Help localized-name cache entry; log off and log on to refresh Explorer."
