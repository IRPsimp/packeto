.386
.model flat, stdcall ;All data and code, including system resources, are in a single 32-bit segment.
;REMOVE SEGMENT REGISTERS ACCESS ERRORS
ASSUME FS:NOTHING

;--------------MACROS(typedefs)-------------
include win_typedefs.inc

INVALID_HANDLE_VALUE equ -1
HEAP_ZERO_MEMORY equ 00000008h

;----------------LIBS---------------
includelib D:\Programs\masm32\lib\kernel32.lib ;Identitfy external library that contains linkages to the windows API
includelib D:\Programs\masm32\lib\msvcrt.lib
includelib Cabinet.lib

;----------------FNC PROTOTYPES---------------
ExitProcess PROTO STDCALL :DWORD;prototype directive -> informs the assembler of the name of an external procedure
CreateFileA PROTO STDCALL :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD ;describe parameter types with :
ReadFile      PROTO STDCALL :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
WriteFile     PROTO STDCALL :DWORD, :DWORD, :DWORD, :DWORD,:DWORD
SetFilePointer PROTO STDCALL :DWORD, :DWORD, :DWORD, :DWORD

CloseHandle PROTO STDCALL :DWORD
GetFileSize   PROTO STDCALL :DWORD, :DWORD
GetProcessHeap PROTO STDCALL
HeapAlloc     PROTO STDCALL :DWORD, :DWORD, :DWORD
HeapFree      PROTO STDCALL :DWORD, :DWORD, :DWORD
GetCommandLineA PROTO STDCALL 
GetLastError PROTO STDCALL

CreateCompressor PROTO STDCALL :DWORD,:DWORD,:DWORD
Compress PROTO STDCALL :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CloseCompressor PROTO STDCALL :DWORD

;msvcrt -> visual c runtime, cdecl
__getmainargs PROTO C :DWORD
printf               PROTO C :DWORD;C = CDECL -> can also use `EXTERN printf :PROC` <- specify the type of symbol
memcpy           PROTO C


;user defined funcs
;----------------ASM-TIME CONSTANTS---------------
HELLO equ 10h ;assembler time constant
NULL   equ 0
STUB_SIZE equ 4

;can also use SEGMENT keyword 
.data
			values        db 16 dup('A')
			proc_infos db  "[~] PID: %d",\
			0Dh,0Ah,"[~] PEB address: 0x%x",0Dh, 0Ah,0
			str_argv     db "[~] File: %s",0Dh, 0Ah,0
			heap_addr  db "[~] HeapAlloc: 0x%x",0Dh,0Ah,0

			dos_sig       db "[~] DOS magic: 0x%x '%s'",0Dh, 0Ah, 0
			dos_lfanew db "[~] DOS e_lfanew: 0x%x",0Dh, 0Ah, 0
			ImageBase_str db "[~] ImageBase: 0x%x",0Dh,0Ah,0
			OEP_str      db "[~] OEP: 0x%x",0Dh,0Ah,0
			file_size_str db "[~] New file size: %d",0Dh,0Ah,0
			size_image_str db "[~] Updated SizeOfImage: 0x%x",0Dh,0Ah,0

			code_seg    db  ".text", 0
			data_seg    db  ".data",0
			rdata_seg   db  ".rdata",0
			packer_seg db  ".pak1",0,0,0
			reloc_seg  db  ".reloc",0
			module1_str db "user32.dll",0
			module2_str db "cabinet.dll",0

			cs_str         db  "[~] Code section: 0x%x",0Dh,0Ah,0
			sec_str       db  "[~] Last section header: 0x%x",0Dh,0Ah,0
			dbg             db  "[~] DBG: 0x%x",0Dh,0Ah,0
			compressed db "[~] Compressed code section Successfully -> %d : %d",0Dh,0Ah,0
			stub_text  db "[~] Wrote text: 0x%x",0Dh,0Ah,0

			handle_str  db "[~] Successfully opened file: 0x%x",0Dh, 0Ah,0
			wroteFile    db "[~] Wrote to file: returned 0x%x -> 0x%x",0Dh,0Ah,0
			fail_handle  db "[~] An error occured: 0x%lx",0  
			fail_section db "[~] Failed adding section: 0x%x",0
			fail_compress db "[~] Failed compressing: 0x%x",0

			stub_copyright db "Protected by ASM_PACKER x86.",0
			str_alloc    db "[~] Str allocated: 0x%x",0Dh,0Ah,0

			shellcode1     db 6Ah,00,6Ah,00,0B8h
			shellcode2     db 50h,6Ah,00,0ffh,15h

.fardata?
			argc    dd ?    
			argv    dd ? ;pointer
			env     dd  ?
			text    db 20  DUP(?)
			mz_sig db 3 DUP(?)

			hFile  dd ? ;a handle is a DWORD on 32-bit
			szFile dd ?
			hCompress dd ?
			compressedSize dd ?

			hHeap  dd ? ;heap handle
			pBuf    dd ? 
			pBuf2   dd ?
			pbuf3   dd ?
			sec_pRaw dd ? ;PointerToRawData of added section
			sec_rSz dd ?   ;raw size of added section
			sec_vsz dd ? ;virtual size of added section
			sec_va  dd ? ;virtual address of added section
			cs_rva dd ?  ;code section rva
			oep_rva dd ? ;entry point rva

			psec_vs DWORD ?

			hDos  IMAGE_DOS_HEADER <> ;init struct using <>1
			hNT   IMAGE_NT_HEADERS  <>
			hFH   IMAGE_FILE_HEADER <>
			hOH32  IMAGE_OPTIONAL_HEADER32 <>
			hCS  IMAGE_SECTION_HEADER <>
			hID  IMAGE_IMPORT_DESCRIPTOR <> ;new import descriptor
			hID2  IMAGE_IMPORT_DESCRIPTOR <> ;new import descriptor
			hITDS IMAGE_THUNK_DATA 4 DUP(<>)
			pSectionHeadersOffset DWORD ? ;address in pBuf where section headers start
			pIMPORT_DESCRIPTORS   DWORD ?
			newSectionOffset      DWORD ?

			pFirstID DWORD ?
			pSecondID DWORD ?
			pIAT_ID DWORD ?
			pIAT_ID2 DWORD ?
			stub_str_va DWORD ?

			pDataDirectory DWORD ?
			pENDofImports DWORD ?


.code ;.text section -> code readable writeable
START:
		mov  eax, dword ptr [values] 	;<-- values is a ptr to a dword!
		mov  eax, dword ptr FS:[20h];Process ID
		mov  edx, dword ptr FS:[30h];PEB of process

		;REMEMBER!: if we pushed a word on the stack then the alignment would be wrong!
		push  edx
		push  eax
		push  OFFSET proc_infos
		call     printf ;cdecl calling convention
		add    esp, 3*4 ;caller cleans stack

		push NULL
		push OFFSET env
		;here argv is a pointer to a table of pointers of the cmdline c strings
		push OFFSET argv
		push OFFSET argc
		call    __getmainargs ;push eip -> jmp to func
		add   esp, 4*4 ;4 args 

		mov   edi, DWORD ptr [argv]
		;+4 since here we are in 32-bit and pointers are 4 bytes long
		push  dword ptr [edi+4]
		push  OFFSET str_argv
		call     printf
		add    esp, 4 * 2 ;2 args

		push 0     ;hTemplateFile
		push 80h ;FILE_ATTRIBUTE_NORMAL
		push 3      ;OPEN_EXISTING
		push 0      ;NO LP_SECURITY_ATTRIBUTES
		push 0      ;FILE_NO_SHARE
		push  80000000h OR 40000000h ;GENERIC_READ | GENERIC_WRITE
		push  DWORD ptr [edi+4] ;argv[1]
		call    CreateFileA ;STDCALL -> callee cleans stack
			
		cmp   eax, INVALID_HANDLE_VALUE
		jz      failed

		mov  DWORD ptr [hFile], eax

		push  DWORD ptr [hFile]
		push  OFFSET handle_str ;address of handle
		call     printf 
		add     esp, 4 * 2 ;CDECL -> caller cleans stack, 2 params

		push  0 ;lpFileSizeHight
		push  DWORD ptr [hFile];hFile
		call     GetFileSize
		mov   DWORD ptr [szFile], eax

		;access public heap
		call  GetProcessHeap ;push eip, jmp GetProcessHeap
		mov DWORD ptr [hHeap], eax

		push DWORD ptr [szFile] ;dwBytes
		push HEAP_ZERO_MEMORY ;dwFlags
		push DWORD ptr [hHeap] ;hHeap
		call   HeapAlloc
		mov  DWORD ptr [pBuf], eax

		push eax
		push OFFSET heap_addr
		call    printf
		add   esp, 4*2

		push 0 ;lpOverlapped
		push 0 ;we ignore that for now
		push DWORD ptr [szFile] ;nbBytesR
		push DWORD ptr [pBuf] ;lpBuf
		push DWORD ptr [hFile] ;Handle
		call    ReadFile

		test  eax, eax
		jz      failed

		;------------INIT PE STRUCTURE-------------
		mov  esi, DWORD ptr [pBuf]
		mov  edi, OFFSET hDos
		mov  ecx, SIZEOF(IMAGE_DOS_HEADER)
		rep   movsb  ;repeat ecx times

		movzx   eax, WORD ptr [hDos.e_magic] ;MZ sig -> 2 bytes
		mov  WORD ptr [mz_sig], ax
		mov  BYTE ptr [mz_sig+2],0 ;null terminator

		rol    ax, 8;since in little endian reverse order -> can also use xchg al,ah

		push OFFSET mz_sig
		push  eax
		push  OFFSET dos_sig ;ADDRESS OF STRING
		call     printf
		add     esp, 4*2

		push  DWORD ptr [hDos.e_lfanew]
		push  OFFSET dos_lfanew
		call     printf
		add     esp, 4*2

		;get offset of IMAGE_NT_HEADER struct
		mov  eax, DWORD ptr [hDos.e_lfanew]
		;LEA resolves address at runtime
		mov  edx, DWORD ptr [pBuf]

		lea    esi, [edx+eax];get address of IMAGE_NT_HEADER
		mov  edi, OFFSET hNT
		mov  ecx, SIZEOF IMAGE_NT_HEADERS
		rep   movsb ;mov byte [edi], byte [esi] ; esi + 1, edi+1, DF

		lea    esi, [hNT.fileHeader];go to the fileHeader struct in NT headers
		mov  edi, OFFSET hFH
		mov  ecx, SIZEOF IMAGE_FILE_HEADER
		rep   movsb ;repeat ecx times

		;hNt+4+SIZEOF IMAGE_FILE_HEADER
		lea    esi, [hNt.OptionalHeader];get to the IMAGE_OPTIONAL_HEADER32 struct
		mov  edi, OFFSET hOH32
		mov  ecx, SIZEOF IMAGE_OPTIONAL_HEADER32
		rep   movsb

		;Get AddressOfEntryPoint and ImageBase
		push  DWORD ptr [hNT.OptionalHeader.ImageBase]
		push  OFFSET ImageBase_str ;address of str
		call    printf
		add   esp, 4 * 2

		mov  eax, DWORD ptr [hNT.OptionalHeader.AddressOfEntryPoint]
		add   eax, DWORD ptr [hNT.OptionalHeader.ImageBase]
		push  eax
		push  OFFSET OEP_str;address of str
		call    printf
		add    esp, 4*2

add_section_header:
		;add section header
		mov eax, DWORD ptr [pBuf]
		mov edx, DWORD ptr [hDos.e_lfanew]
		lea   esi, [eax+edx+SIZEOF IMAGE_NT_HEADERS]
		mov DWORD ptr [pSectionHeadersOffset],esi

		push esi
		call    GetLastSectionHeader

		mov  DWORD ptr [newSectionOffset],eax

		;Name + Code Size
		mov edi, eax
		mov esi, OFFSET packer_seg
		mov ecx, SIZEOF  packer_seg
		rep  movsb

		mov DWORD ptr [edi],STUB_SIZE

		;Virtual
		mov eax, DWORD ptr [newSectionOffset]
		sub  eax, SIZEOF IMAGE_SECTION_HEADER

		lea   ecx, [eax+OFFSET IMAGE_SECTION_HEADER.VirtualSize]
		mov ecx, DWORD ptr [ecx] ;VirtualSize of last section

		lea   edx, [eax+OFFSET IMAGE_SECTION_HEADER.VirtualAddress];VirtualAddress
		mov edx, DWORD ptr [edx] ;VirtualAddress of last section

		mov  ebx, edx
		add  ebx, ecx

		;round up section
		mov eax, ebx
		mov ecx, DWORD ptr [hNT.OptionalHeader.SectionAlignment]
		cdq ;clear divisor
		div  ecx ;edx,eax <- edx:eax / ecx

		;align
		sub  ebx, edx
		add  ebx, ecx

		mov DWORD ptr [sec_va],ebx
		mov DWORD ptr [edi+4],ebx

        ;RAW
        mov eax, DWORD ptr [newSectionOffset]
        sub  eax, SIZEOF IMAGE_SECTION_HEADER

		lea   edx, [eax+OFFSET IMAGE_SECTION_HEADER.PointerToRawData];get to the pointer to raw data field
		mov edx, DWORD ptr [edx] ;PointerToRawData of last section

		lea   ecx, [eax+OFFSET IMAGE_SECTION_HEADER.SizeOfRawData]
		mov ecx, DWORD ptr [ecx] ;SizeOfRawData of last section

		mov DWORD ptr [sec_rSz],ecx

		add  edx, ecx

		mov DWORD ptr [sec_pRaw],edx

		mov DWORD ptr [edi+8],ecx ;SizeOfRawData -> last section raw size
		mov DWORD ptr [edi+0Ch],edx   ;PointerToRawData -> last section pointer to raw + sizeofrawdata

		sub   eax, DWORD ptr [pBuf] ;get the absolute offset of the section after the last section header
		push  eax
		push OFFSET sec_str
		call    printf
		add   esp, 4*2

		;Relocations and lineNumbers
		mov DWORD ptr [edi+10h],0
		mov DWORD ptr [edi+14h],0
		mov DWORD ptr [edi+18h],0

		;Characteristics
		;WRITE |INITIALIZED_DATA | CODE | READ | EXECUTE
		mov DWORD ptr [edi+1Ch],80000000h OR 00000040h OR 00000020h OR 40000000h OR 20000000h

update_headers:
		;Update executable's File Headers
		mov  edx, DWORD ptr [pBuf]
		mov eax, DWORD ptr [hDos.e_lfanew]
		lea   esi, [edx+eax]

		;increase NumberOfSections
		mov eax, DWORD ptr [hNT.fileHeader.NumberOfSections]
		inc   eax
		mov DWORD ptr [esi+OFFSET IMAGE_NT_HEADERS.FileHeader+OFFSET IMAGE_FILE_HEADER.NumberOfSections],eax

		;SizeOfHeaders
		mov eax, DWORD ptr [hNT.OptionalHeader.SizeOfHeaders]
		add  eax, SIZEOF IMAGE_SECTION_HEADER

		;align
		mov ebx, eax
		mov ecx, DWORD ptr [hNT.OptionalHeader.FileAlignment]
		cdq ;clear divisor
		div  ecx ;edx,eax <- edx:eax / ecx

		sub  ebx, edx
		add  ebx, ecx

		mov DWORD ptr [esi+OFFSET IMAGE_NT_HEADERS.OptionalHeader+ OFFSET IMAGE_OPTIONAL_HEADER32.SizeOfHeaders],ebx

		;SizeOfCode		
		mov  eax, DWORD ptr [hNT.OptionalHeader.SizeOfCode]
		add   eax, DWORD ptr [sec_rSz] ;Raw Size of added section
		mov  DWORD ptr [esi+OFFSET IMAGE_NT_HEADERS.OptionalHeader+OFFSET IMAGE_OPTIONAL_HEADER32.SizeOfCode],ebx

		;increase SizeOfImage (size when loaded in memory)
		mov  eax, DWORD ptr [sec_va]
		;https://reverseengineering.stackexchange.com/questions/12121/how-can-file-size-and-pe-size-cant-be-equal
		add   eax, STUB_SIZE ;last section is the added section

		;round up section
		mov ebx, eax
		mov ecx, DWORD ptr [hNT.OptionalHeader.SectionAlignment]
		cdq ;clear divisor
		div  ecx ;edx,eax <- edx:eax / ecx

		;align -> (original_size - modulo) + section alignment
		sub  ebx, edx
		add  ebx, ecx
		mov  DWORD ptr [esi+OFFSET IMAGE_NT_HEADERS.OptionalHeader+OFFSET IMAGE_OPTIONAL_HEADER32.SizeOfImage],ebx

		push  DWORD ptr [hNt.OptionalHeader.SizeOfImage]
		call DebugPrint

		push  ebx
		push  OFFSET size_image_str
		call 	  printf
		add    esp, 4*2

do_compression:
;iterate over other sections
		movzx  edx, WORD ptr [hNT.fileHeader.NumberOfSections]
		;Get first section header
		mov eax, DWORD ptr [pBuf]
		mov edx, DWORD ptr [hDos.e_lfanew]
		lea   esi, [eax+edx+SIZEOF IMAGE_NT_HEADERS]
		;section name to compare to
		mov  edi, OFFSET code_seg

iterate_sections:
		mov ecx, SIZEOF code_seg
		;Apparently when stepping into repz the zero flag is not updated, at least on windbg
		repz cmpsb

		jz    found_code_section
		;get back to original address of Name address 
		sub   ecx, SIZEOF code_seg
		neg   ecx
		sub   esi, ecx 
		;restore the edi offset
		mov edi, OFFSET code_seg

		add esi, SIZEOF IMAGE_SECTION_HEADER ;go to next section header

		dec edx
		jnz  iterate_sections

		;loop   iterate_sections ;dec ecx, jnz label
found_code_section:
		;get start of IMAGE_SECTION_HEADER structure
		sub   ecx, SIZEOF code_seg ;abs(address-counter)
		neg   ecx
		sub   esi, ecx 

		;copy the structure in hCS
		mov  edi, OFFSET hCS
		mov  ecx, SIZEOF IMAGE_SECTION_HEADER
		rep    movsb

		push  DWORD ptr [hCS.VirtualAddress]
		push  OFFSET cs_str
		call    printf
		add    esp, 4*2

		mov  eax, DWORD ptr [pBuf]
		add  eax, DWORD ptr [hCS.PointerToRawData]
		mov  DWORD ptr [cs_rva], eax

compress_code_section:
		;xor code section and replace EP by shellcode in the custom section that decrypts the code section
		;it then VirtualAllocs the size of the code section and runs it in memory
		push  OFFSET hCompress
		push 0
		push 2 ;COMPRESS_ALGORITHM_MSZIP
		call    CreateCompressor

		push DWORD ptr [hCS.SizeOfRawData];dwBytes
		push 8 ;HEAP_ZERO_MEMORY
		push DWORD ptr [hHeap]
		call   HeapAlloc
		mov DWORD ptr [pBuf3], eax

		push DWORD ptr [hCS.VirtualSize] ;count
		push DWORD ptr [cs_rva] ;src -> code section in pBuf
		push  DWORD ptr [pBuf3];dest
		call memcpy
		add esp, 4*3

		push OFFSET compressedSize ;CompressedDataSize
		;push DWORD ptr [hCS.SizeOfRawData] ;CompressedBufferSize
		push DWORD ptr [hCS.SizeOfRawData]
		push DWORD ptr [pBuf3] ;CompressedBuffer
		push DWORD ptr [hCS.VirtualSize]
		push  DWORD ptr [pBuf3]
		push DWORD ptr [hCompress]
		call  Compress

		test eax, eax
		jz   failed_compressing

		push compressedSize
		push DWORD ptr [hCS.VirtualSize]
		push OFFSET compressed
		call    printf
		add   esp, 4

		;copy compressed code section in file buffer
		push DWORD ptr [hCS.SizeOfRawData] ;count
		push DWORD ptr [pBuf3] ;src
		push DWORD ptr [cs_rva] ;dest
		call   memcpy
		add  esp, 4*3

		;free compressors
		push DWORD ptr [hCompress]
		call  CloseCompressor

		;dealloc HeapBuffer
		push DWORD ptr [pBuf3]
		push 0
		push DWORD ptr [hHeap]
		call   HeapFree

		;Update section virtual size
		push OFFSET code_seg
		call GetSectionHeaderOffset

		mov  edx, DWORD ptr [compressedSize]
		mov  DWORD ptr [eax+OFFSET IMAGE_SECTION_HEADER.virtualSize],edx


craft_shellcode:
		;save entry point RVA
		mov  eax, DWORD ptr [hNT.OptionalHeader.BaseOfCode]
		sub  eax, DWORD ptr [hNT.OptionalHeader.AddressOfEntryPoint]
		neg  eax
		mov  DWORD ptr [oep_rva], eax

prepare_imports:
		;make addSection function

		;Create new import descriptor for user32.dll
		mov  DWORD ptr [hID.ImportNameTableRVA],0DEADBEEFh ;PLACEHOLDER
		mov  DWORD ptr [hID.TimeDateStamp],0
		mov  DWORD ptr [hID.ForwarderChain],0
		mov  DWORD ptr [hID.Name1],0 ;PLACEHOLDER
		mov  DWORD ptr [hID.ImportAddressTableRVA],0DEADBEEFh ;PLACEHOLDER

		;Create new import descriptor for cabinet.dll
		mov  DWORD ptr [hID2.ImportNameTableRVA],0DEADBEEFh ;PLACEHOLDER
		mov  DWORD ptr [hID2.TimeDateStamp],0
		mov  DWORD ptr [hID2.ForwarderChain],0
		mov  DWORD ptr [hID2.Name1],0
		mov  DWORD ptr [hID2.ImportAddressTableRVA],0DEADBEEFh ;PLACEHOLDER

		;null DIR entry

		;Create IMAGE_THUNK_DATA for Import descriptor pointers -> DLL1 Import Lookup Table
		mov   DWORD ptr [hITDS], 865h OR 80000000h ;SET ordinal flag and give ordinal number of MessageBoxA
		
		;null byte

		;DLL2 Import Lookup Table
		mov   DWORD ptr [hITDS+4], 28h OR 80000000h ;SET ordinal flag and give ordinal number of CreateDecompressor
		mov   DWORD ptr [hITDS+8], 2Bh OR 80000000h ;SET ordinal flag and give ordinal number of Decompress
		mov   DWORD ptr [hITDS+0Ch], 2Dh OR 80000000h ;SET ordinal flag and give ordinal number of CloseCompressor
		;null byte

		;WE DON'T HAVE A HINT/NAME TABLE

add_imports:
		;=======GENERAL structure of imports=======
		;List of import descriptors
		;empty import descriptor -> null structure
		;module name of import 1
			;-> if imported by name
			;Hint/Name table list
				;hint word then func name 
			;IMPORT Lookup Table list
				;pointers to Hint/Name tables
			;null hint/name table
			;IMPORT Address Table list
				;pointers to Hint/name tables -> same as Import Lookup Table until loader overwrites it
			
			;Empty IMAGE_THUNK_DATA
		;------------------------------------
			;-> if imported by ordinal
			;Import lookup Table list
				;ordinals with the MSB set
			;Empty IMAGE_THUNK_DATA
			;Import Address Table list
				;ordinals with MSB -> same as ILT until runtime

			;Empty IMAGE_THUNK_DATA

		;module name of import 2
			;same as above
		;etc...

		;maybe imports are higher than rSZ -> TODO: check
		push DWORD ptr [sec_rSz]
		push 8 ;HEAP_ZERO_MEMORY
		push DWORD ptr [hHeap]
		call HeapAlloc

		mov  DWORD ptr [pBuf2],eax

copy_existing_import_directory_tables:	
		mov  edx, DWORD ptr [pBuf]
		mov  eax, DWORD ptr [hDos.e_lfanew]
		lea  esi, [edx+eax+18h+OFFSET IMAGE_OPTIONAL_HEADER32.DataDirectory]

		mov  DWORD ptr [pDataDirectory],esi

		mov  eax, DWORD ptr [esi+1*SIZEOF IMAGE_DATA_DIRECTORY] ;Get VirtualAddress of Import Data Directory
		mov  ecx, DWORD ptr [esi+1*SIZEOF IMAGE_DATA_DIRECTORY+OFFSET IMAGE_DATA_DIRECTORY.VirtualSize] ;Get virtualSize

		;Change them to our shellcode section
		mov ebx, DWORD ptr [sec_va]
		mov DWORD ptr [esi+1*SIZEOF IMAGE_DATA_DIRECTORY],ebx

		lea ebx, [ecx+3*SIZEOF IMAGE_IMPORT_DESCRIPTOR] ; 2 dll imports
		mov DWORD ptr [esi+1*SIZEOF IMAGE_DATA_DIRECTORY+OFFSET IMAGE_DATA_DIRECTORY.VirtualSize],ebx

		;Get raw address of beginning of the IMPORT_DIRECTORY_TABLE
		push eax
		call VAtoRAW

		push eax
		call DebugPrint

		;copy Import Directory Table to new section
		lea  esi, [edx+eax]
		mov  edi, DWORD ptr [pBuf2]
		;we insert the IMPORT_DESCRIPTORS copy after the existing ones
		rep  movsb

		;since we have one empty IMAGE_IMPORT_DIRECTORY
		sub  edi, SIZEOF IMAGE_IMPORT_DESCRIPTOR
		mov DWORD ptr [pFirstID], edi

check_if_already_has_imports:
	;TODO: CHECK if the PE already imports user32.dll or cabinet.dll
	;IF yes, only add import lookup table (IMAGE_THUNK_DATA) with ordinal of function after import lookup tables list
	;dont forget to add null lookup table after added one

add_new_imports_descriptors:
		;we copy our additional imports

		;user32.dll
		lea  esi, [hID]
		;edi is pointing after the copied import descriptors
		mov  ecx, SIZEOF hID 
		rep  movsb

		mov DWORD ptr [pSecondID], edi

		;cabinet.dll
		mov  esi, OFFSET hID2 ;same as lea esi, [hID2]
		;edi is pointing after previously copied import descriptor
		mov  ecx, SIZEOF hID2
		rep  movsb

		;Store null IMAGE_IMPORT_DESCRIPTOR structure
		mov  al, 0
		mov  ecx, SIZEOF IMAGE_IMPORT_DESCRIPTOR
		rep  stosb

		;First module import name
		mov  esi, OFFSET module1_str
		mov  ecx, SIZEOF module1_str
		rep  movsb

		;Import lookup table list
		mov  esi, OFFSET hITDS
		mov  ecx, 4
		rep  movsb

		;null import lookup table
		mov al, 0
		mov ecx, 4
		rep stosb

		mov DWORD ptr [pIAT_ID],edi
		;Import Address Table
		mov esi, OFFSET hITDS
		mov ecx, 4
		rep movsb

		;null IMAGE_THUNK_DATA
		mov al, 0
		mov ecx, 4
		rep stosb

;cabinet.dll
		;First module import name
		mov  esi, OFFSET module2_str
		mov  ecx, SIZEOF module2_str
		rep  movsb

		;Import lookup table list
		lea  esi, [hITDS+4]
		mov  ecx, 4*3
		rep  movsb

		;null import lookup table
		mov al, 0
		mov ecx, 4
		rep stosb

		mov DWORD ptr [pIAT_ID2],edi
		;Import Address Table
		lea  esi, [hITDS+4]
		mov  ecx, 4*3
		rep  movsb

		;null IMAGE_THUNK_DATA
		mov al, 0
		mov ecx, 4
		rep stosb	

		mov DWORD ptr [pENDofImports], edi

parse_new_imports:
		;First import descriptor
		push DWORD ptr [pFirstID]
		push SIZEOF module1_str
		push OFFSET module1_str
		call FindStr 

		mov esi, DWORD ptr [pFirstID]

		;express the addresses as RVA's inside the PE file, instead of absolute addresses inside the read buffer
		mov edi, eax
		sub edi, DWORD ptr [pBuf2]
		add edi, DWORD ptr [sec_va]

		;replace Import Lookup Table
		lea edx, [edi+SIZEOF module1_str]

		mov DWORD ptr [esi], edx

		;update NameRVA
		mov DWORD ptr [esi+OFFSET IMAGE_IMPORT_DESCRIPTOR.Name1],edi

		;update Import Address Table
		mov  edx, DWORD ptr [pIAT_ID]
		sub  edx, DWORD ptr [pBuf2]
		add  edx, DWORD ptr [sec_va]

		mov DWORD ptr [esi+OFFSET IMAGE_IMPORT_DESCRIPTOR.ImportAddressTableRVA],edx
;------------------
		push DWORD ptr [pSecondID]
		push SIZEOF module2_str
		push OFFSET module2_str
		call FindStr

		mov esi, DWORD ptr [pSecondID]

		;express the addresses as RVA's inside the PE file, instead of absolute addresses inside the read buffer
		mov edi, eax
		sub edi, DWORD ptr [pBuf2]
		add edi, DWORD ptr [sec_va]

		;Update import lookup table RVA
		lea edx, [edi+SIZEOF module2_str]

		mov DWORD ptr [esi],edx 

		;Update NameRVA field
		mov DWORD ptr [esi+OFFSET IMAGE_IMPORT_DESCRIPTOR.Name1],edi

		mov edx, DWORD ptr [pIAT_ID2]
		sub edx, DWORD ptr [pBuf2]
		add edx, DWORD ptr [sec_va]

		;Update ImportAddressTableRVA RVA field
		mov  DWORD ptr [esi+OFFSET IMAGE_IMPORT_DESCRIPTOR.ImportAddressTableRVA],edx

update_pe_headers:
		;Increase SizeOfInitializedData with import descriptors in pak0 section
		;change entry point to shellcode
		;change BaseOfCode

		mov esi, DWORD ptr [pBuf]
		mov eax, DWORD ptr [hDos.e_lfanew]
		lea edi, [esi+eax+OFFSET IMAGE_NT_HEADERS.OptionalHeader+OFFSET IMAGE_OPTIONAL_HEADER32.SizeOfInitializedData]

		add DWORD ptr [edi], SIZEOF stub_copyright

		push DWORD ptr [esi+eax+OFFSET IMAGE_NT_HEADERS.OptionalHeader+OFFSET IMAGE_OPTIONAL_HEADER32.FileAlignment] 
		push DWORD ptr [edi]
		call AlignValue

		mov  DWORD ptr [edi], eax

		;update BaseOfCode and AddressOfEntryPoint
		mov esi, DWORD ptr [pBuf2]
		mov edx, DWORD ptr [pENDofImports]
		sub edx, esi

		add edx, DWORD ptr [sec_va]

		mov esi, DWORD ptr [pBuf]
		mov eax, DWORD ptr [hDos.e_lfanew]

		mov DWORD ptr [esi+eax+OFFSET IMAGE_NT_HEADERS.OptionalHeader+OFFSET IMAGE_OPTIONAL_HEADER32.AddressOfEntryPoint],edx

		mov edx, DWORD ptr [sec_va]
		mov DWORD ptr [esi+eax+OFFSET IMAGE_NT_HEADERS.OptionalHeader+OFFSET IMAGE_OPTIONAL_HEADER32.BaseOfCode],edx

add_copyright_text:
		;GEt .data section header
		push OFFSET rdata_seg
		call GetSectionHeaderOffset

		;get to the uninitialized space
		mov  esi, DWORD ptr [eax+OFFSET IMAGE_SECTION_HEADER.PointerToRawData]
		mov  ecx, DWORD ptr [eax+OFFSET IMAGE_SECTION_HEADER.virtualSize]
		mov  edi, DWORD ptr [pBuf]

find_code_cave:

		;TODO: make find code cave function 
			;-> if virtual size of data > raw size search in other sections and not in reloc since we use it later
		;implement check_if_already_has_imports
		;Encrypt text,bss,data and rdata(after copying the imports) using a random 8 byte xor key before compression 
		;Update the virtual size of these sections with the compressedSize of compress func
		;add the decompressor functionality to the shellcode
		;Review code -> clean it and structure it, make functions if repetitions

		;copy string to the uninitialized space
		lea  edx, [esi+ecx]

		push edx
		call RAWtoVA  
		mov  DWORD ptr [stub_str_va],eax

		add  edi, edx

		;Calculate the address of string inside the read file buffer

		;copy the string at the appropriate address INSIDE the read buffer
		mov  esi, OFFSET stub_copyright
		mov  ecx, SIZEOF stub_copyright
		rep  movsb

		;Increase the VirtualSize of the data section
		push OFFSET data_seg
		call GetSectionHeaderOffset

		add  DWORD ptr [eax+OFFSET IMAGE_SECTION_HEADER.virtualSize], SIZEOF stub_copyright

		push DWORD ptr [stub_str_va]
		call DebugPrint


make_shellcode:
		;call them on the compressed text section
		;virtual alloc a buffer of virtual size of the code section 
		;call the RVA of entry point from the allocated buffer 
		;put shellcode in .pak0 section

		mov esi, DWORD ptr [pBuf2]
		mov eax, DWORD ptr [pENDofImports]

		mov esi, OFFSET shellcode1
		mov edi, eax
		mov ecx, SIZEOF shellcode1
		rep movsb

		mov  esi, DWORD ptr [stub_str_va]

		add  esi, DWORD ptr [hOH32.ImageBase] 

		mov  DWORD ptr [edi],esi
		add  edi, 4

		mov  esi, OFFSET shellcode2
		mov  ecx, SIZEOF shellcode2
		rep  movsb

		push 865h OR 80000000h
		call GetFunctionVAFromImports

		cmp  eax, 0FFFFFFFFh
		jz   failed_add_section

		add  eax, DWORD ptr [hOH32.ImageBase]

		mov  DWORD ptr [edi],eax

		push eax
		call DebugPrint

		;Update virtualSize of added section
		sub  edi, DWORD ptr [pBuf2]

		push OFFSET packer_seg
		call GetSectionHeaderOffset

		add  DWORD ptr [eax+OFFSET IMAGE_SECTION_HEADER.virtualSize],edi
		mov  DWORD ptr [sec_vsz], edi

add_reloc:
		mov esi, DWORD ptr [sec_va]

		push OFFSET reloc_seg
		call GetSectionHeaderOffset

		mov edi, DWORD ptr [eax+OFFSET IMAGE_SECTION_HEADER.VirtualAddress]
		add edi, DWORD ptr [eax+OFFSET IMAGE_SECTION_HEADER.virtualSize]

		push edi
		call VAtoRAW	

		push eax
		call DebugPrint

		mov edi, eax
		add edi, DWORD ptr [pBuf]

		mov eax, edi
		cdq
		mov ecx, 32
		div ecx ; edx, eax <- eax / ecx

		test edx, edx
		jnz  on_32bit_boundary

not_on_32bit_boundary:
		sub edi, edx
		add edi, ecx

on_32bit_boundary: 
		mov eax, DWORD ptr [sec_va]
		mov DWORD ptr [edi], eax

		push OFFSET packer_seg
		call GetSectionHeaderOffset

		mov DWORD ptr [edi+4],8 ;2 entries + size of fixup block

		mov eax, DWORD ptr [pBuf]
		mov edx, DWORD ptr [hDos.e_lfanew]
		add eax, edx

		mov eax, DWORD ptr [eax+18h+OFFSET IMAGE_OPTIONAL_HEADER32.AddressOfEntryPoint]
		add eax, SIZEOF shellcode1

		sub eax, DWORD ptr [sec_va]

		push eax 
		call DebugPrint

		mov edx, eax
		or  dx, 3000h;IMAGE_REL_BASED_HIGHLOW, high 4 bits are equal to 3

		mov WORD ptr [edi+8],dx

		add eax, 4
		add eax, SIZEOF shellcode2

		push eax 
		call DebugPrint

		or  ax, 3000h

		mov WORD ptr [edi+0Ah],ax

		;update reloc section virtual size
		push OFFSET reloc_seg
		call GetSectionHeaderOffset

		lea edx, [edi+0Ah]
		sub edx, edi

		add DWORD ptr [eax+OFFSET IMAGE_SECTION_HEADER.virtualSize],edx

		;update reloc DATA Directory
		mov eax, DWORD ptr [pDataDirectory]

		lea eax, [eax+5*SIZEOF IMAGE_DATA_DIRECTORY+4]
		add DWORD ptr [eax], edx

add_section:
		push 2 ;FILE_END
		push 0 ;no high order dword
		push 0;offset
		push DWORD ptr [hFile]
		call   SetFilePointer

		push 0
		push 0
		push DWORD ptr [sec_rSz]
		push DWORD ptr [pBuf2]
		push DWORD ptr [hFile]
		call    WriteFile

		mov  edx, eax
		call  GetLastError

		push eax
		push edx
		push OFFSET wroteFile
		call printf
		add  esp,4*3

		push  DWORD ptr [pBuf2]
		push  0
		push  DWORD ptr [hHeap]
		call  HeapFree

		push 0
		push DWORD ptr [hFile]
		call    GetFileSize

		cmp  eax, DWORD ptr [szFile]
		jz      failed_add_section

update_file:
		push 0 ;FILE_BEGIN
		push 0
		push 0
		push DWORD ptr [hFile]
		call    SetFilePointer

		push 0
		push 0
		push DWORD ptr [szFile]
		push DWORD ptr [pBuf]
		push DWORD ptr [hFile]
		call    WriteFile

		;free allocated heap buffer
		push  DWORD ptr [pBuf] ;lpAddress
		push  0  ;dwFlags
		push  DWORD ptr [hHeap]
		call     HeapFree

		;close file Handle
		push DWORD PTR [hFile]
		call   CloseHandle
		jmp  exit

failed_compressing:
		call GetLastError

		push eax
		push OFFSET fail_compress
		call   printf
		add   esp, 4*2
		jmp   exit

failed_add_section:
		call GetLastError
		
		push eax
		push OFFSET fail_section
		call   printf
		add   esp, 4*2
		jmp  exit
failed:
		call GetLastError

		push  eax
		push OFFSET fail_handle ;address of str
		call   printf
		add   esp, 4*2

exit:
		push 0                  ;since x86
		call    [ExitProcess] ;return cpu control to windows

DebugPrint PROC
		push ebp
		mov  ebp, esp
		pushad

		push DWORD ptr [ebp+8]
		push OFFSET dbg
		call    printf
		add   esp, 4*2

		popad
		mov  esp, ebp
		pop   ebp
		ret    4
DebugPrint ENDP

;GetFunctionVAFromImports (DWORD ordinal)
GetFunctionVAFromImports PROC
		push ebp
		mov  ebp, esp ;create stack frame
		push esi
		push edx
		push ebx
		push ecx
		push edi

		mov  eax, DWORD ptr [ebp+8]
		mov  esi, DWORD ptr [pBuf2]
		xor  ecx, ecx

loop_INT:
		;Get INT of each imported modules
		mov  edi, DWORD ptr [esi+OFFSET IMAGE_IMPORT_DESCRIPTOR.ImportNameTableRVA]

		test edi, edi
		jz   failed_find_offset
		
		;push edi
		;call DebugPrint

		cmp  edi, DWORD ptr [sec_va]
		jb   native_rva

added_section_rva:
		sub  edi, DWORD ptr [sec_va]
		add  edi, DWORD ptr [sec_pRaw]
		jmp  continue_rva

native_rva: ;can be accessed through pBuf
		;Transform the Virtual Address of the INT into an address in the read buffer
		push edi
		call VAtoRAW

		mov  edi, eax

continue_rva:
		cmp  edi, DWORD ptr [sec_pRaw]
		ja   added_import

normal_import:
		add  edi, DWORD ptr [pBuf]
		jmp  check_import_type

added_import:
		sub  edi, DWORD ptr [sec_pRaw]
		add  edi, DWORD ptr [pBuf2]

check_import_type:
		mov  edx, DWORD ptr [edi]
		and  edx, 80000000h ;check if msb is set with this mask
		jnz   is_imported_by_ordinal

is_imported_by_name: 
		;skip import descriptor
		;we skip it even if the import descriptor has also ordinal imports
		add esi, SIZEOF IMAGE_IMPORT_DESCRIPTOR
		jmp loop_INT

is_imported_by_ordinal:
		mov  eax, DWORD ptr [ebp+8]

find_ordinal_offset:

		cmp  DWORD ptr [edi], eax
		jz   found_ordinal_offset

		cmp  DWORD ptr [edi],00000000
		jz   next_import_descriptor

		add  edi, SIZEOF DWORD ;next import lookup table
		inc  ecx ;increase offset
		jmp  find_ordinal_offset

next_import_descriptor:
		cmp  DWORD ptr [esi],0
		jz   failed_find_offset ;we reached the end of the import descriptors

		add  esi, SIZEOF IMAGE_IMPORT_DESCRIPTOR

		jmp  loop_INT

found_ordinal_offset:
		mov  ebx, DWORD ptr [esi+OFFSET IMAGE_IMPORT_DESCRIPTOR.ImportAddressTableRVA]

		lea  eax, [ebx+ecx*SIZEOF DWORD]

		jmp finish
failed_find_offset:
		mov eax, -1

finish:
		pop edi
		pop ecx
		pop ebx
		pop edx
		pop esi
		mov  esp, ebp ;balance stack
		pop  ebp ;restore prev stack frame
		ret  4  ;STDCALL!
GetFunctionVAFromImports ENDP

;AlignValue(DWORD_PTR Address, LONG alignment)
AlignValue PROC
	push ebp
	mov  ebp, esp
	push edx
	push ebx

	mov ebx, DWORD ptr [ebp+8]
	mov edx, DWORD ptr [ebp+0Ch]

	mov eax, ebx
	mov ecx, edx
	cdq ;clear divisor
	div ecx ;edx,eax <- edx:eax / ecx

	;align
	sub  ebx, edx
	add  ebx, ecx

	mov  eax, ebx

	pop  ebx
	pop  edx
	mov  esp, ebp
	pop  ebp
	ret  8
AlignValue ENDP

;FindStr(DWORD_PTR c_str, SIZE_T c_str_len, DWORD_PTR start_offset)
FindStr PROC
	push ebp
	mov  ebp, esp

	mov esi, DWORD ptr [ebp+8]
	mov edi, DWORD ptr [ebp+10h]
	mov ecx, DWORD ptr [ebp+0Ch]

loop_str: 
	repz cmpsb
	jz found_str

	mov esi, DWORD ptr [ebp+8]
	mov ecx, DWORD ptr [ebp+0Ch]
	jmp loop_str

found_str:
	sub edi,DWORD ptr [ebp+0Ch]
	mov eax,edi

	mov esp, ebp
	pop ebp
	ret 8
FindStr ENDP

;GetSectioOffset(SectionName)
GetSectionHeaderOffset PROC
		push ebp
		mov  ebp, esp
		sub  esp, 4
		push ecx
		push edx
		push esi
		push edi

		mov  esi, DWORD ptr [pSectionHeadersOffset] ;in pBuf
		mov  edi, DWORD ptr [ebp+8]	
get_strlen:
		mov  ecx, 10
		mov  al, 0 ;null term
		repne scasb

		sub  ecx, 10
		neg  ecx

		mov  DWORD ptr [ebp-4],ecx
		mov  edi, DWORD ptr [ebp+8]
find_section:
		push esi ;some backup

		repz cmpsb
		jz  found_section

		pop esi
		add esi, SIZEOF IMAGE_SECTION_HEADER
		mov edi, DWORD ptr [ebp+8]
		mov ecx, DWORD ptr [ebp-4]

		jmp find_section

found_section:
		pop eax

		pop edi
		pop esi
		pop edx
		pop ecx
		mov esp, ebp
		pop ebp
		ret 4
GetSectionHeaderOffset ENDP

;DWORD_PTR stdcall VAtoRAW(DWORD_PTR VA)
VAtoRAW PROC
		push ebp
		mov  ebp, esp
		push edx
		push ecx

		mov  eax, DWORD ptr [ebp+8] ;VA
		mov  edx, DWORD ptr [pSectionHeadersOffset]
		movzx  ecx, WORD ptr [hNT.fileHeader.NumberOfSections]

iter:
		cmp  DWORD ptr [edx+SIZEOF IMAGE_SECTION_HEADER+0Ch],eax ;IMAGE_SECTION_HEADER.VirtualAddress 
		ja    found     

		add   edx, SIZEOF IMAGE_SECTION_HEADER
		jmp iter

found:
		sub  eax, DWORD ptr [edx+0Ch]
		add  eax, DWORD ptr [edx+OFFSET IMAGE_SECTION_HEADER.PointerToRawData]

		pop ecx
		pop edx
		mov  esp, ebp
		pop   ebp
		ret    4
VAtoRAW ENDP

;RAWtoVA(DWORD_PTR fileOffset)
RAWtoVA PROC
	push ebp
	mov  ebp, esp
	push edx
	push ecx

	mov   eax, DWORD ptr [ebp+8]
	mov   edx, DWORD ptr [pSectionHeadersOffset]
	movzx ecx, WORD ptr [hNT.fileHeader.NumberOfSections]

iter:
	cmp  DWORD ptr [edx+SIZEOF IMAGE_SECTION_HEADER+OFFSET IMAGE_SECTION_HEADER.PointerToRawData],eax 
	ja   found     

	;address is nearest to the last section
	dec  ecx
	jz   found

	add   edx, SIZEOF IMAGE_SECTION_HEADER
	jmp iter

found:
	sub  eax, DWORD ptr [edx+OFFSET IMAGE_SECTION_HEADER.PointerToRawData]
	add  eax, DWORD ptr [edx+OFFSET IMAGE_SECTION_HEADER.VirtualAddress]

	pop ecx
	pop edx
	mov esp, ebp
	pop ebp
	ret 4
RAWtoVA ENDP

;GetLastSection(PVOID start_of_section_headers)
GetLastSectionHeader PROC 
			push ebp
			mov  ebp, esp
			sub   esp, 4*2
			;ebp,ret addy, params
			mov  eax, DWORD ptr [ebp+8]

iter:
			cmp  BYTE ptr [eax], 0
			jz found
			add  eax, SIZEOF IMAGE_SECTION_HEADER
			jmp  iter 

found:
			mov  esp, ebp
			pop ebp
			ret 4 ;1 param
GetLastSectionHeader ENDP

END START