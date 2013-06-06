.386
.model flat,stdcall
option casemap:none
include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\comdlg32.inc
include \masm32\include\user32.inc
includelib \masm32\lib\user32.lib
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\comdlg32.lib

IDD_MAINDLG  equ	101
IDC_EDIT	equ	1000
IDM_OPEN	equ	40001
IDM_EXIT	equ	40003
IDM_EXPORT	equ	40004
IDM_IMPORT	equ	40005
IDM_ST		equ	40006

DlgProc			proto :DWORD,:DWORD,:DWORD,:DWORD
OpenPeFile		proto :DWORD
ShowExport		proto :DWORD,:DWORD
ShowImport		proto :DWORD,:DWORD
ShowSectionInfo	proto :DWORD
AppendText		proto :DWORD,:DWORD


SEH struct
	PrevLink dd ?		; the address of the previous seh structure
	CurrentHandler dd ?	; the address of the new exception handler
	SafeOffset dd ?	; The offset where it's safe to continue execution
	PrevEsp dd ?		; the old value in esp
	PrevEbp dd ?		; The old value in ebp
SEH ends


.data
AppName db "PE file inspector",0
ofn   OPENFILENAME <>
FilterString	db "Executable Files (*.exe, *.dll)",0,"*.exe;*.dll",0
				db "All Files",0,"*.*",0,0
FileOpenError 			db "Cannot open the file for reading",0             
FileOpenMappingError	db "Cannot open the file for memory mapping",0
FileMappingError		db "Cannot map the file into memory",0
NotValidPE 				db "This file is not a valid PE",0
OpenPE					db "Open PE file first",0
NoExportTable			db "No export information in this file",0
CRLF 		db 0Dh,0Ah,0
;;;EXPORT;;;
ExportTable db 0Dh,0Ah,"======[ IMAGE_EXPORT_DIRECTORY ]======",0Dh,0Ah 
			db "Name of the module: %s",0Dh,0Ah
			db "nBase: %lu",0Dh,0Ah
			db "NumberOfFunctions: %lu",0Dh,0Ah
			db "NumberOfNames: %lu",0Dh,0Ah
			db "AddressOfFunctions: %lX",0Dh,0Ah
			db "AddressOfNames: %lX",0Dh,0Ah
			db "AddressOfNameOrdinals: %lX",0Dh,0Ah,0
Header		db "RVA	Ord.	Name",0Dh,0Ah
			db "----------------------------------------------",0
template	db "%lX	%u	%s",0
;;;IMPORT;;;;
ImportDescriptor db 0Dh,0Ah,"================[ IMAGE_IMPORT_DESCRIPTOR ]=============",0
IDTemplate	db "OriginalFirstThunk  =  %lX",0Dh,0Ah
			db "TimeDateStamp  =  %lX",0Dh,0Ah
			db "ForwarderChain = %lX",0Dh,0Ah
			db "Name = %s",0Dh,0Ah
			db "FirstThunk = %lX",0
NameHeader	db 0Dh,0Ah,"Hint	Function",0Dh,0Ah
			db "-----------------------------------------",0
NameTemplate	db "%u	%s",0
OrdinalTemplate db "%u	(ord.)",0
;;;SECTION TABLE;;;
SHeader		db "Section	V.Size		V.Address		Raw Size		Raw Offset		Characteristics",0Dh,0Ah
			db "-=-	-=-		-=-			-=-		-=-			-=-",0 
STemplate	db "	%lX 		%lX			%lX		%lX			%lX",0
.data?
buffer db 512 dup(?)
hFile dd ?
hMapping dd ?
pMapping dd ?
ValidPE dd ?
NTHdr dd ?
NumberOfSections dw ?

.code
start:
	invoke GetModuleHandle,NULL
	invoke DialogBoxParam, eax, IDD_MAINDLG,NULL,addr DlgProc, 0
	invoke ExitProcess, 0	
NoPe proc
	invoke MessageBox,0, addr OpenPE, addr AppName,MB_OK
	Ret
NoPe EndP
	
DlgProc proc hDlg:DWORD, uMsg:DWORD, wParam:DWORD, lParam:DWORD		
	.if uMsg==WM_INITDIALOG
		invoke SendDlgItemMessage,hDlg,IDC_EDIT,EM_SETLIMITTEXT,0,0
	.elseif uMsg==WM_CLOSE
		invoke UnmapViewOfFile, pMapping
		invoke EndDialog,hDlg,0
	.elseif uMsg==WM_COMMAND
		.if lParam==0
			mov eax,wParam
			.if ax==IDM_OPEN
				invoke OpenPeFile,hDlg
			.elseif ax==IDM_EXPORT
				.if ValidPE==TRUE
					invoke ShowExport, hDlg, NTHdr
				.else
					invoke NoPe
				.endif
			.elseif ax==IDM_IMPORT
				.if ValidPE==TRUE
					invoke ShowImport, hDlg, NTHdr
				.else
					invoke NoPe
				.endif
			.elseif ax==IDM_ST
				.if ValidPE==TRUE
					invoke ShowSectionInfo, hDlg
				.else
					invoke NoPe
				.endif
						
			.elseif ax==IDM_EXIT
				invoke SendMessage,hDlg,WM_CLOSE,0,0
			.endif
		.endif
	.else
		mov eax,FALSE
		ret
	.endif
	mov eax,TRUE
	ret
DlgProc endp	
	
SEHHandler proc uses edx pExcept:DWORD,pFrame:DWORD,pContext:DWORD,pDispatch:DWORD
	mov edx,pFrame		
	assume edx:ptr SEH
	mov eax,pContext
	assume eax:ptr CONTEXT
	push [edx].SafeOffset
	pop [eax].regEip
	push [edx].PrevEsp
	pop [eax].regEsp
	push [edx].PrevEbp
	pop [eax].regEbp
	mov ValidPE, FALSE
	mov eax,ExceptionContinueExecution
	ret
SEHHandler endp

OpenPeFile proc uses edi  hDlg:DWORD
	LOCAL seh:SEH
	mov	ofn.lStructSize,SIZEOF ofn
	mov	ofn.lpstrFilter, OFFSET FilterString
	mov	ofn.lpstrFile, OFFSET buffer
	mov	ofn.nMaxFile,512
	mov	ofn.Flags, OFN_FILEMUSTEXIST or \
                       OFN_PATHMUSTEXIST or OFN_LONGNAMES or\
                       OFN_EXPLORER or OFN_HIDEREADONLY
	invoke GetOpenFileName, ADDR ofn
	.if eax==TRUE
		invoke CreateFile, addr buffer, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
		.if eax!=INVALID_HANDLE_VALUE
			mov hFile, eax
			invoke CreateFileMapping, hFile, NULL, PAGE_READONLY,0,0,0
			.if eax!=NULL
				mov hMapping, eax
				invoke MapViewOfFile,hMapping,FILE_MAP_READ,0,0,0
				.if eax!=NULL
					mov pMapping,eax
					assume fs:nothing
					push fs:[0]
					pop seh.PrevLink
					mov seh.CurrentHandler,offset SEHHandler
					mov seh.SafeOffset,offset FinalExit
					lea eax,seh
					mov fs:[0], eax
					mov seh.PrevEsp,esp
					mov seh.PrevEbp,ebp
					mov edi, pMapping
					assume edi:ptr IMAGE_DOS_HEADER
					.if [edi].e_magic==IMAGE_DOS_SIGNATURE
						add edi, [edi].e_lfanew
						assume edi:ptr IMAGE_NT_HEADERS
						.if [edi].Signature==IMAGE_NT_SIGNATURE
							mov ValidPE, TRUE
						.else
							mov ValidPE, FALSE
						.endif
					.else
						mov ValidPE,FALSE
					.endif
FinalExit:
					push seh.PrevLink
					pop fs:[0]
					mov NTHdr,edi
					.if ValidPE==TRUE
						;invoke MessageBox,0, addr FileValidPE, addr AppName,MB_OK
					.else
						invoke MessageBox,0, addr NotValidPE, addr AppName,MB_OK+MB_ICONERROR
					.endif
				.else
					invoke MessageBox, 0, addr FileMappingError, addr AppName,MB_OK+MB_ICONERROR
				.endif
				invoke CloseHandle,hMapping
			.else
				invoke MessageBox, 0, addr FileOpenMappingError, addr AppName,MB_OK+MB_ICONERROR
			.endif
			invoke CloseHandle, hFile
		.else
			invoke MessageBox, 0, addr FileOpenError, addr AppName, MB_OK+MB_ICONERROR
		.endif
	.endif	
	ret
OpenPeFile endp

AppendText proc hDlg:DWORD,pText:DWORD	
	invoke SendDlgItemMessage,hDlg,IDC_EDIT,EM_REPLACESEL,0,pText
	invoke SendDlgItemMessage,hDlg,IDC_EDIT,EM_REPLACESEL,0,addr CRLF
	invoke SendDlgItemMessage,hDlg,IDC_EDIT,EM_SETSEL,-1,0
	ret
AppendText endp

RVAToFileMap PROC uses edi esi edx ecx pFileMap:DWORD,RVA:DWORD
	mov esi,pFileMap
	assume esi:ptr IMAGE_DOS_HEADER
	add esi,[esi].e_lfanew
	assume esi:ptr IMAGE_NT_HEADERS
	mov edi,RVA	; edi == RVA
	mov edx,esi
	add edx,sizeof IMAGE_NT_HEADERS
	mov cx,[esi].FileHeader.NumberOfSections
	movzx ecx,cx
	assume edx:ptr IMAGE_SECTION_HEADER
	.while ecx>0	; check all sections
		.if edi>=[edx].VirtualAddress
			mov eax,[edx].VirtualAddress
			add eax,[edx].SizeOfRawData
			.if edi<eax	; The address is in this section
				mov eax,[edx].VirtualAddress
				sub edi,eax	; edi == difference between the specified RVA and the section's RVA
				mov eax,[edx].PointerToRawData
				add eax,edi	; eax == file offset
				add eax,pFileMap
				ret
			.endif
		.endif
		add edx,sizeof IMAGE_SECTION_HEADER
		dec ecx
	.endw
	assume edx:nothing
	assume esi:nothing
	mov eax,edi
	ret
RVAToFileMap endp

RVAToOffset PROC uses edi esi edx ecx pFileMap:DWORD,RVA:DWORD
	mov esi,pFileMap
	assume esi:ptr IMAGE_DOS_HEADER
	add esi,[esi].e_lfanew
	assume esi:ptr IMAGE_NT_HEADERS
	mov edi,RVA	; edi == RVA
	mov edx,esi
	add edx,sizeof IMAGE_NT_HEADERS
	mov cx,[esi].FileHeader.NumberOfSections
	movzx ecx,cx
	assume edx:ptr IMAGE_SECTION_HEADER
	.while ecx>0	; check all sections
		.if edi>=[edx].VirtualAddress
			mov eax,[edx].VirtualAddress
			add eax,[edx].SizeOfRawData
			.if edi<eax	; The address is in this section
				mov eax,[edx].VirtualAddress
				sub edi,eax	; edi == difference between the specified RVA and the section's RVA
				mov eax,[edx].PointerToRawData
				add eax,edi	; eax == file offset
				ret
			.endif
		.endif
		add edx,sizeof IMAGE_SECTION_HEADER
		dec ecx
	.endw
	assume edx:nothing
	assume esi:nothing
	mov eax,edi
	ret
RVAToOffset endp

ShowExport proc uses esi ecx ebx hDlg:DWORD, pNTHdr:DWORD
	LOCAL temp[512]:BYTE
	LOCAL NumberOfNames:DWORD
	LOCAL Base:DWORD
	
	mov edi,pNTHdr
	assume edi:ptr IMAGE_NT_HEADERS
	mov edi, [edi].OptionalHeader.DataDirectory.VirtualAddress
	.if edi==0
		invoke MessageBox,0, addr NoExportTable,addr AppName,MB_OK+MB_ICONERROR
		ret		
	.endif
	invoke SetDlgItemText,hDlg,IDC_EDIT,0
	invoke AppendText,hDlg,addr buffer
	invoke RVAToFileMap,pMapping,edi
	mov edi,eax
	assume edi:ptr IMAGE_EXPORT_DIRECTORY
	mov eax,[edi].NumberOfFunctions
	invoke RVAToFileMap, pMapping,[edi].nName
	invoke wsprintf, addr temp,addr ExportTable,eax,[edi].nBase,[edi].NumberOfFunctions,[edi].NumberOfNames,[edi].AddressOfFunctions,[edi].AddressOfNames,[edi].AddressOfNameOrdinals
	invoke AppendText,hDlg,addr temp
	invoke AppendText,hDlg,addr Header
	push [edi].NumberOfNames
	pop NumberOfNames
	push [edi].nBase
	pop Base
	invoke RVAToFileMap,pMapping,[edi].AddressOfNames
	mov esi,eax
	invoke RVAToFileMap,pMapping,[edi].AddressOfNameOrdinals
	mov ebx,eax
	invoke RVAToFileMap,pMapping,[edi].AddressOfFunctions
	mov edi,eax
	.while NumberOfNames>0				
		invoke RVAToFileMap,pMapping,dword ptr [esi]
		mov dx,[ebx]
		movzx edx,dx
		mov ecx,edx
		add ecx,Base
		shl edx,2
		add edx,edi
		invoke wsprintf, addr temp,addr template,dword ptr [edx],ecx,eax
		invoke AppendText,hDlg,addr temp
		dec NumberOfNames
		add esi,4
		add ebx,2
	.endw
	ret
ShowExport endp

ShowImport proc uses esi ecx ebx hDlg:DWORD, pNTHdr:DWORD
	LOCAL temp[512]:BYTE
	invoke SetDlgItemText,hDlg,IDC_EDIT,0
	invoke AppendText,hDlg,addr buffer
	mov edi,pNTHdr
	assume edi:ptr IMAGE_NT_HEADERS
	mov edi, [edi].OptionalHeader.DataDirectory[sizeof IMAGE_DATA_DIRECTORY].VirtualAddress
	invoke RVAToOffset,pMapping,edi
	mov edi,eax
	add edi,pMapping
	assume edi:ptr IMAGE_IMPORT_DESCRIPTOR
	.while !([edi].OriginalFirstThunk==0 && [edi].TimeDateStamp==0 && [edi].ForwarderChain==0 && [edi].Name1==0 && [edi].FirstThunk==0)
		invoke AppendText,hDlg,addr ImportDescriptor
		invoke RVAToOffset,pMapping, [edi].Name1
		mov edx,eax
		add edx,pMapping
		invoke 	wsprintf, addr temp, addr IDTemplate,[edi].OriginalFirstThunk,[edi].TimeDateStamp,[edi].ForwarderChain,edx,[edi].FirstThunk
		invoke AppendText,hDlg,addr temp
		.if [edi].OriginalFirstThunk==0
			mov esi,[edi].FirstThunk
		.else
			mov esi,[edi].OriginalFirstThunk
		.endif
		invoke RVAToOffset,pMapping,esi
		add eax,pMapping
		mov esi,eax
		invoke AppendText,hDlg,addr NameHeader
		.while dword ptr [esi]!=0
			test dword ptr [esi],IMAGE_ORDINAL_FLAG32
			jnz ImportByOrdinal
			invoke RVAToOffset,pMapping,dword ptr [esi]
			mov edx,eax
			add edx,pMapping
			assume edx:ptr IMAGE_IMPORT_BY_NAME
			mov cx, [edx].Hint
			movzx ecx,cx
			invoke wsprintf,addr temp,addr NameTemplate,ecx,addr [edx].Name1
			jmp ShowTheText
ImportByOrdinal:
			mov edx,dword ptr [esi]
			and edx,0FFFFh
			invoke wsprintf,addr temp,addr OrdinalTemplate,edx
ShowTheText:			
			invoke AppendText,hDlg,addr temp
			add esi,4
		.endw				
		add edi,sizeof IMAGE_IMPORT_DESCRIPTOR
	.endw
	ret
ShowImport endp

ShowSectionInfo proc uses esi edi eax hDlg:DWORD
	LOCAL temp[512]:BYTE
	LOCAL NameBuf[8]:BYTE
	mov edi, pMapping
	assume edi:ptr IMAGE_DOS_HEADER
	add edi, [edi].e_lfanew
	assume edi:ptr IMAGE_NT_HEADERS
	mov ax,[edi].FileHeader.NumberOfSections
	mov NumberOfSections,ax
	add edi,sizeof IMAGE_NT_HEADERS
	;mov esi,edi
	assume edi:ptr IMAGE_SECTION_HEADER
	mov ax, NumberOfSections
	movzx eax,ax
	mov esi,eax
	invoke SetDlgItemText,hDlg,IDC_EDIT,0
	invoke AppendText,hDlg,addr SHeader
	.while esi>0
		invoke lstrcpyn,addr NameBuf,addr [edi].Name1,8
		invoke SendDlgItemMessage,hDlg,IDC_EDIT,EM_REPLACESEL,0,addr NameBuf
		invoke SendDlgItemMessage,hDlg,IDC_EDIT,EM_SETSEL,-1,0
		invoke wsprintf, addr temp,addr STemplate,[edi].Misc.VirtualSize,[edi].VirtualAddress,[edi].SizeOfRawData,[edi].PointerToRawData,[edi].Characteristics
		invoke AppendText,hDlg,addr temp
		dec esi
		add edi, sizeof IMAGE_SECTION_HEADER
	.endw
	;invoke DialogBoxParam, hInstance, IDD_SECTIONTABLE,NULL, addr DlgProc, edi
	ret
ShowSectionInfo endp
end start
