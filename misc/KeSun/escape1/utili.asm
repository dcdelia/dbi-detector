IFDEF RAX

ELSE
.686 
.MODEL FLAT, C
assume fs:nothing 
ENDIF



.CODE

WriteEscape PROC public
	
	int 3
	;mov eax, dword ptr [esp+4]

	;db 090h
	;db 090h
	;db 0ffh
	db 0e8h
	dd 01210000h
	
	ret

WriteEscape ENDP




END
