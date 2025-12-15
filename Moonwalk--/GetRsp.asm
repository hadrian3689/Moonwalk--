.code

get_current_rsp proc
	mov     rax, rsp
    add     rax, 8
    ret
get_current_rsp endp

end