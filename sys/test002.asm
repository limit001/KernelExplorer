
section .text
bits 64

global nasm_farjmp
global nasm_farjmp2es

nasm_retfq:
	push 30h
	push rcx
	retfq
ret

nasm_farjmp:
	
	mov rcx, 0h
	db 0ffh
	db 00h
	db 00h
	db 00h
	db 00h
	db 030h
	db 00h

	db 0ffh
	db 25h
	db 00h
	db 00h
	db 00h
	db 000h

ret

nasm_farjmp2fs:	
;	mov ax,30h
;	mov fs,ax
	db 64h
	db 0ffh
	db 24h
	db 25h
	db 00h
	db 00h
	db 00h
	db 00h
ret

nasm_farjmp2es:	
	mov ax,30h
;	mov fs,ax
	db 26h
	db 0ffh
	db 24h
	db 25h
	
	db 00h
	db 00h
	db 00h
	db 00h
	db 00h


ret