#NoEnv
SendMode Input
SetWorkingDir %A_ScriptDir%


Run "steam://run/553850"
Process, Wait, helldivers2.exe
run, %comspec% /c frida "helldivers2.exe" -l leemdivers.js