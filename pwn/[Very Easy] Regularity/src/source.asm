section .data
    message1 db 'Hello, Survivor. Anything new these days?',0xA     ; Message 1 followed by newline
    len1 equ $ - message1                                           ; Length of message 1

    message3 db 'Yup, same old same old here as well...',0xA        ; Message 3 followed by newline
    len3 equ $ - message3

section .text
    global _start

_start:
    ; Print message 1
    mov rdi, 1                        ; file descriptor 1 is stdout
    mov rsi, message1                 ; pointer to message 1
    mov rdx, len1                     ; length of message 1
    call write                ; call write function

    ; Read string from user
    call read                 ; call read function

    ; Print message 3
    mov rdi, 1                        ; file descriptor 1 is stdout
    mov rsi, message3                 ; pointer to message 3
    mov rdx, len3                     ; length of message 3
    call write                ; call write function

    mov rsi, exit
    jmp rsi

; Function for write syscall
write:
    mov eax, 1                        ; syscall number for sys_write
    syscall                           ; perform syscall
    ret                               ; return from function

; Function for read syscall
read:
    sub rsp, 256                      ; Reserve 256 bytes on stack for the input
    mov eax, 0                        ; syscall number for sys_read
    mov rdi, 0                        ; file descriptor 0 is stdin
    lea rsi, [rsp]                    ; pointer to top of stack (input buffer)
    mov rdx, 272                      ; maximum number of bytes to read - 0x10 too many
    syscall                           ; perform syscall
    add rsp, 256                      ; Clean up stack
    ret                               ; return from function

exit:
    ; Exit program
    mov eax, 60                       ; syscall number for sys_exit
    xor edi, edi                      ; status 0, zero out the register
    syscall