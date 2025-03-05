# MedievalDynasty-RestoreCheatMenu

NOTE:  The latest release stopped working with MD 2.3.0.7.  Stick with an earlier game version if you want to keep using this until this gets updated.



DLL to restore the ingame cheat menu.


Steam will want xinput1_3.dll, MS Store version will want xinput1_4.dll.

When launching the game with the DLL in place a black console window should appear.  If you do not see this window, the game likely failed to find the DLL.

For the MS Store version, drop xinput1_4.dll in the folder:
	C:\XboxGames\Medieval Dynasty\Content

For the Steam version, drop xinput1_3.dll in the folder:
	....Wherever Steam wants it.  Let me know where works and I'll update this.
	
NOTE:  For Steam/GOG do not drop xinput1_3.dll in the folder with the Medieval_Dynasty.exe, it should go in the subfolder "Medieval_Dynasty\Binaries\Win64" alongside Medieval_Dynasty-Win64-Shipping.exe.
