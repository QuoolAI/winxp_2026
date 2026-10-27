' Read-only observation. This is not a Winlogon admission decision.
' Do not call Activate*, SetProductKey, or change licensing registry data.
Option Explicit
On Error Resume Next
Dim service, rows, row
Set service = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
If Err.Number <> 0 Then
  WScript.Echo "XP25_POLICY_OBSERVATION connect_error=" & Hex(Err.Number)
  WScript.Quit 1
End If
Set rows = service.ExecQuery("SELECT ActivationRequired, RemainingGracePeriod, RemainingEvaluationPeriod FROM Win32_WindowsProductActivation")
If Err.Number <> 0 Then
  WScript.Echo "XP25_POLICY_OBSERVATION query_error=" & Hex(Err.Number)
  WScript.Quit 2
End If
For Each row In rows
  WScript.Echo "XP25_POLICY_OBSERVATION ActivationRequired=" & row.ActivationRequired & " RemainingGracePeriod=" & row.RemainingGracePeriod & " RemainingEvaluationPeriod=" & row.RemainingEvaluationPeriod
Next
If Err.Number <> 0 Then
  WScript.Echo "XP25_POLICY_OBSERVATION enumeration_error=" & Hex(Err.Number)
  WScript.Quit 3
End If
WScript.Echo "XP25_POLICY_OBSERVATION read_only_complete"
