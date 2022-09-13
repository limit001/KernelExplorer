

.data

EXTERN g_pOld80:DQ;

save_sp			dq	0
save_rdx		dq	0
save_rip		dq	0
GdtPtr64	    dw	0
		        dd	0
jump_value      dq  0
                dw  30h
JMPPOS DB  00h, 00h, 00h, 00h, 00h,00h,30h,00h  ;the address to be jumped to  1234:5678

.code
CpuBack PROC   
	push	rbp
	mov		rbp, rsp
;	Save SS
	push	rax
	mov		ax,	ss
	mov		qword ptr [rcx+(23*8)], rax

;	Save SP
	mov		rax, rbp
	add		rax, 16
	mov		qword ptr [rcx+(22*8)], rax

;	flags
	pushfq
	pop		rax
	mov		qword ptr [rcx+(21*8)], rax

;	save CS
	mov		ax, cs
	mov		qword ptr [rcx+(20*8)], rax

;	save rip
	mov		rax, qword ptr [rbp + 8]
	mov		qword ptr [rcx+(19*8)], rax

	pop		rax
	pop		rbp


	add		rcx, (19*8)
	mov		rsp, rcx
	sub		rcx, (19*8)

	push	rbp
    push	rax
    push	rbx
    push	rcx
    push	rdx
    push	rdi
    push	rsi
    push	r8
    push	r9
    push	r10
    push	r11
    push	r12
    push	r13
    push	r14
    push	r15
    
    mov		ax, ds      ; DS 세그먼트 셀렉터와 ES 세그먼트 셀렉터는 스택에 직접
    push	rax        ; 삽입할 수 없으므로, RAX 레지스터에 저장한 후 스택에 삽입
    mov		ax, es
    push	rax
    push	fs
    push	gs 

	;Load New Task Cpu Infomation
	mov		rsp, rdx
    pop		gs
    pop		fs
    pop		rax
    mov		es, ax      ; ES 세그먼트 셀렉터와 DS 세그먼트 셀렉터는 스택에서 직접
    pop		rax         ; 꺼내 복원할 수 없으므로, RAX 레지스터에 저장한 뒤에 복원
    mov		ds, ax
    
    pop		r15
    pop		r14
    pop		r13
    pop		r12
    pop		r11
    pop		r10
    pop		r9
    pop		r8
    pop		rsi
    pop		rdi
    pop		rdx
    pop		rcx
    pop		rbx
    pop		rax
    pop		rbp    
    iretq
CpuBack ENDP

UserModeCpuBack PROC   
	push	rbp
	mov		rbp, rsp

	push	rax

	;save rip
	mov		rax, qword ptr [rbp + 8]
	mov		qword ptr [rcx+(16*8)], rax

	;save rbp+16 (8*2 2개 올라간다!!!스택을~~!!)
	;save sp 
	mov		rax, rbp
	add		rax, 16		; 8*2
	mov		qword ptr [rcx+(15*8)], rax

	pop		rax
	pop		rbp

	mov		save_sp, rsp

	add		rcx, (15*8)	;15개 더한다. 왜냐구? 스택은 위에서 내려오니까..
	mov		rsp, rcx
	sub		rcx, (15*8)

	push	rbp		;#01
    push	rax		;#02
    push	rbx		;#03
    push	rcx		;#04
    push	rdx		;#05
    push	rdi		;#06
    push	rsi		;#07
    push	r8		;#08
    push	r9		;#09
    push	r10		;#10
    push	r11		;#11
    push	r12		;#12
    push	r13		;#13
    push	r14		;#14
    push	r15		;#15
;	mov		rsp,	save_sp
;	ret
	;Load New Task Cpu Infomation
	mov		rsp, qword ptr [rdx+16*8]
	mov		save_rip, rsp
	mov		rsp, rdx
   
    pop		r15
    pop		r14
    pop		r13
    pop		r12
    pop		r11
    pop		r10
    pop		r9
    pop		r8
    pop		rsi
    pop		rdi
    pop		rdx
    pop		rcx
    pop		rbx
    pop		rax
    pop		rbp
	pop		rsp
	push	rax
	mov		rax, save_rip
	mov		qword ptr [rsp+8], rax
	pop		rax
	ret

UserModeCpuBack ENDP

IretTest PROC

	iretd

IretTest ENDP

RetTest PROC
	push	rbp
	mov		rbp, rsp
	mov		rax, qword ptr [rbp+8]
	mov		rbx, IretTest
	mov		qword ptr [rcx],rbx
	mov		rsp, rcx
	ret
RetTest ENDP

Int3 PROC
    int     3
	ret
Int3 ENDP

Read60h PROC    
    xor     rax, rax
    in      al, 60h    
	ret
Read60h ENDP

Write60h PROC
    xor     rax, rax
    or      al, 111b
    out     60h,al
	ret
Write60h ENDP

Write64h PROC
    xor     rax, rax
    mov     al, 0FEh
    out     64h,al
	ret
Write64h ENDP

Write64h60h PROC
    xor     rax, rax
    mov     al, 060h
    out     64h,al
	ret
Write64h60h ENDP

Write64habh PROC
    xor     rax,rax
    mov     al,0abh
    out     64h,al
    ret
Write64habh ENDP

;void Write43h(QWORD	qwData);
Write43h PROC
;   rcx
;   ecx
;   cx
;   ch 
;   cl
    mov     al, cl
    out     43h,al
	ret
Write43h ENDP
;void Write40h(QWORD	qwData);
Write40h PROC
;   rcx
;   ecx
;   cx
;   ch 
;   cl
    mov     al, cl
    out     40h,al
	ret
Write40h ENDP


; USHORT __stdcall AsmReadLDTR();
AsmReadLDTR PROC
    sldt ax
    ret
AsmReadLDTR ENDP

;void __sgdt(	void * 	gdtr	)
__sgdt PROC
	sgdt	[rcx]
	ret
__sgdt ENDP

;void __sgdt	(	_Out_ void * 	gdtr	)
__sidt PROC
	sidt	[rcx]
	ret
__sidt ENDP

test001 PROC
    mov es, ax
;    MOV ax, dword ptr es:[11111]
test001 ENDP

farjmp PROC
    push 0ffffh
    push 30h
    retf    
farjmp ENDP

farjmp2 PROC
    jmp qword ptr [JMPPOS]
farjmp2 ENDP

;__int64 ReadCr3()
ReadCr3 PROC
	mov	rax, cr3
	ret
ReadCr3 ENDP

;__int64 ReadCr0()
ReadCr0 PROC
	mov	rax, cr0
	ret
ReadCr0 ENDP

;__int64 ReadCr4()
ReadCr4 PROC
	mov	rax, cr4
	ret
ReadCr4 ENDP

DisableWP PROC
    mov rax, cr0
;    and eax, 0FFFFFFFFFFFEFFFFh
    and rax, 0FFFEFFFFh
    mov cr0, rax
DisableWP ENDP

EnableWP PROC
    mov rax, cr0
    or rax, 0000000000010000h
    mov cr0, rax
EnableWP ENDP

Old80   PROC
    jmp g_pOld80
Old80   ENDP
END


