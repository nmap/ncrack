; Automatically generated from nsis/Ncrack.nsi.in.
;Ncrack Installer 
;-------------------------------- 
;Include Modern UI 
 
  !include "MUI.nsh" 
  !include "AddToPath.nsh" 
 
;-------------------------------- 
;General 
 
  ;Name and file 
  Name "Ncrack" 
  OutFile "NcrackInstaller.exe" 

  ;Required for removing shortcuts
  RequestExecutionLevel admin

  ;Default installation folder 
  InstallDir "$PROGRAMFILES\Ncrack" 
   
  ;Get installation folder from registry if available 
  InstallDirRegKey HKCU "Software\Ncrack" "" 
 
  !define VERSION "0.7"
  VIProductVersion "0.7.0.0"
  VIAddVersionKey /LANG=1033 "FileVersion" "${VERSION}"
  VIAddVersionKey /LANG=1033 "ProductName" "Ncrack" 
  VIAddVersionKey /LANG=1033 "CompanyName" "Insecure.org" 
  VIAddVersionKey /LANG=1033 "InternalName" "NcrackInstaller.exe" 
  VIAddVersionKey /LANG=1033 "LegalCopyright" "Copyright (c) Insecure.Com LLC (fyodor@insecure.org)" 
  VIAddVersionKey /LANG=1033 "LegalTrademark" "NCRACK" 
  VIAddVersionKey /LANG=1033 "FileDescription" "Ncrack installer" 
   
;-------------------------------- 
;Interface Settings 
 
  !define MUI_ABORTWARNING 
 
;-------------------------------- 
;Pages 
 
  !insertmacro MUI_PAGE_LICENSE "..\LICENSE" 
  !insertmacro MUI_PAGE_COMPONENTS 
  !insertmacro MUI_PAGE_DIRECTORY 
  !insertmacro MUI_PAGE_INSTFILES 
  !insertmacro MUI_UNPAGE_CONFIRM 
  !insertmacro MUI_UNPAGE_INSTFILES 
  Page custom finalPage doFinal
   
;-------------------------------- 
;Languages 
  
  !insertmacro MUI_LANGUAGE "English" 

;--------------------------------
;Reserves

ReserveFile "final.ini"
!insertmacro MUI_RESERVEFILE_INSTALLOPTIONS

;--------------------------------
;Functions

Function .onInit
  !insertmacro MUI_INSTALLOPTIONS_EXTRACT "final.ini"
FunctionEnd


Function finalPage
  ; diplay a page saying everything's finished
  !insertmacro MUI_HEADER_TEXT "Finished" "Thank you for installing Ncrack"
  !insertmacro MUI_INSTALLOPTIONS_DISPLAY "final.ini"
FunctionEnd

Function doFinal
 ; don't need to do anything
FunctionEnd

;-------------------------------- 
;Installer Sections 
 
Section "Ncrack Core Files" SecCore 

  StrCpy $R0 $INSTDIR "" -2
  StrCmp $R0 ":\" bad_key_install
  StrCpy $R0 $INSTDIR "" -14
  StrCmp $R0 "\Program Files" bad_key_install
  StrCpy $R0 $INSTDIR "" -8
  StrCmp $R0 "\Windows" bad_key_install
  StrCpy $R0 $INSTDIR "" -6
  StrCmp $R0 "\WinNT" bad_key_install
  StrCpy $R0 $INSTDIR "" -9
  StrCmp $R0 "\system32" bad_key_install
  StrCpy $R0 $INSTDIR "" -8
  StrCmp $R0 "\Desktop" bad_key_install
  StrCpy $R0 $INSTDIR "" -22
  StrCmp $R0 "\Documents and Settings" bad_key_install
  StrCpy $R0 $INSTDIR "" -13
  StrCmp $R0 "\My Documents" bad_key_install probably_safe_key_install
  bad_key_install:
    MessageBox MB_YESNO "It may not be safe to uninstall the previous installation of Ncrack from the directory '$INSTDIR'.$\r$\nContinue anyway (not recommended)?" IDYES probably_safe_key_install 
    Abort "Install aborted by user" 
  probably_safe_key_install:

  SetOutPath "$INSTDIR" 

  SetOverwrite on 
  File ..\..\COPYING 
  File /r /x .svn ..\..\lists
  File ..\..\ncrack-services 
  File ..\Release\ncrack.exe
  File ..\Release\libssl-1_1.dll
  File ..\Release\libcrypto-1_1.dll
  
  ;Store installation folder 
  WriteRegStr HKCU "Software\Ncrack" "" $INSTDIR 

  ;Create uninstaller 
  WriteUninstaller "$INSTDIR\Uninstall.exe" 
   
  ; Register Ncrack with add/remove programs 
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Ncrack" "DisplayName" "Ncrack ${VERSION}" 
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Ncrack" "UninstallString" '"$INSTDIR\uninstall.exe"' 
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Ncrack" "NoModify" 1 
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Ncrack" "NoRepair" 1 
SectionEnd 
 
Section "Register Ncrack Path" SecRegisterPath 
  PUSH $INSTDIR 
  Call AddToPath 
SectionEnd 
 
;-------------------------------- 
;Descriptions 
 
  ;Component strings 
  LangString DESC_SecCore ${LANG_ENGLISH} "Installs Ncrack executable"
  LangString DESC_SecRegisterPath ${LANG_ENGLISH} "Registers Ncrack path to System path so you can execute it from any directory" 

  ;Assign language strings to sections 
  !insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN 
    !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} $(DESC_SecCore) 
    !insertmacro MUI_DESCRIPTION_TEXT ${SecRegisterPath} $(DESC_SecRegisterPath) 
  !insertmacro MUI_FUNCTION_DESCRIPTION_END 
;-------------------------------- 
;Uninstaller Section 
 
Section "Uninstall" 

  StrCpy $R0 $INSTDIR "" -2
  StrCmp $R0 ":\" bad_key_uninstall
  StrCpy $R0 $INSTDIR "" -14
  StrCmp $R0 "\Program Files" bad_key_uninstall
  StrCpy $R0 $INSTDIR "" -8
  StrCmp $R0 "\Windows" bad_key_uninstall
  StrCpy $R0 $INSTDIR "" -6
  StrCmp $R0 "\WinNT" bad_key_uninstall
  StrCpy $R0 $INSTDIR "" -9
  StrCmp $R0 "\system32" bad_key_uninstall
  StrCpy $R0 $INSTDIR "" -8
  StrCmp $R0 "\Desktop" bad_key_uninstall
  StrCpy $R0 $INSTDIR "" -22
  StrCmp $R0 "\Documents and Settings" bad_key_uninstall
  StrCpy $R0 $INSTDIR "" -13
  StrCmp $R0 "\My Documents" bad_key_uninstall probably_safe_key_uninstall
  bad_key_uninstall:
    MessageBox MB_YESNO "It may not be safe to uninstall Ncrack from the directory '$INSTDIR'.$\r$\nContinue anyway (not recommended)?" IDYES probably_safe_key_uninstall 
    Abort "Uninstall aborted by user" 
  probably_safe_key_uninstall:

  IfFileExists $INSTDIR\ncrack.exe ncrack_installed 
    MessageBox MB_YESNO "It does not appear that Ncrack is installed in the directory '$INSTDIR'.$\r$\nContinue anyway (not recommended)?" IDYES ncrack_installed 
    Abort "Uninstall aborted by user" 

  SetDetailsPrint textonly 
  DetailPrint "Uninstalling Files..." 
  SetDetailsPrint listonly 
   
  ncrack_installed: 
  Delete "$INSTDIR\COPYING" 
  Delete "$INSTDIR\ncrack.exe"
  RMDir /r "$INSTDIR\lists"
  Delete "$INSTDIR\ncrack-services" 
  Delete "$INSTDIR\README-WIN32" 
  Delete "$INSTDIR\libssl-1_1.dll"
  Delete "$INSTDIR\libcrypto-1_1.dll"
  Delete "$INSTDIR\Uninstall.exe" 

  ;Removes folder if it's now empty
  RMDir "$INSTDIR"
 
  SetDetailsPrint textonly 
  DetailPrint "Deleting Registry Keys..." 
  SetDetailsPrint listonly 
  DeleteRegKey /ifempty HKCU "Software\Ncrack" 
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Ncrack" 
  SetDetailsPrint textonly 
  DetailPrint "Unregistering Ncrack Path..." 
  Push $INSTDIR 
  Call un.RemoveFromPath 

  RMDIR "$SMPROGRAMS\Ncrack"

  SetDetailsPrint both 
SectionEnd 
