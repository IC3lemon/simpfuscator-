import sys
import lief
import tempfile
import subprocess
import shutil
import os
from encryptor import *
from typing import List, Tuple, Optional

# DIET_LIBC_PATH = os.environ.get("DIET_LIBC_PATH")
# if not DIET_LIBC_PATH:
#     print("Error: DIET_LIBC_PATH environment variable not set.")
#     print("Please set it to the root of your dietlibc installation.")
#     sys.exit(1)

LOADER_DIR = os.path.join(os.path.dirname(__file__), "loader")
LOADER_BINARY = os.path.join(LOADER_DIR, "loader.elf")

PAGE_SIZE = 0x1000

def compile_c_string(
    c_source: str,
    output_path: Optional[str] = None,
    compiler: str = "gcc",
    flags: Optional[List[str]] = None,
    extra_env: Optional[dict] = None,
    workdir: Optional[str] = None,
) -> Tuple[bool, str, str, Optional[str]]:
    """Returns (success, stdout, stderr, output_path)."""
    if shutil.which(compiler) is None:
        return False, "", f"Compiler {compiler} not found in PATH", None

    flags = flags or []
    cleanup_dir = False
    if workdir is None:
        tmpdir = tempfile.mkdtemp(prefix="ccompile_")
        cleanup_dir = True
    else:
        tmpdir = workdir
        os.makedirs(tmpdir, exist_ok=True)

    src_path = os.path.join(tmpdir, "gen.c")
    try:
        with open(src_path, "w", encoding="utf-8") as f:
            f.write(c_source)

        if output_path is None:
            output_path = os.path.join(tmpdir, "a.out")

        cmd = [compiler, src_path, "-o", output_path] + flags

        env = os.environ.copy()
        if extra_env:
            env.update(extra_env)

        proc = subprocess.run(cmd, cwd=tmpdir, env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        success = proc.returncode == 0

        if success and os.path.exists(output_path):
            os.chmod(output_path, 0o755)

        return success, proc.stdout, proc.stderr, (output_path if success else None)

    finally:
        if cleanup_dir:
            pass  

def bytes_to_c_array(b: bytes, per_line: int = 12) -> str:
    parts = []
    for i in range(0, len(b), per_line):
        chunk = b[i:i+per_line]
        parts.append(", ".join(f"0x{byte:02x}" for byte in chunk))
    inner = ",\n    ".join(parts) if parts else ""
    return "{\n    " + inner + "\n}"

symbols = ['xor', 'rsa'] # fuckass
class Obfuscator:

    def __init__(self, filename):
        self.filename = filename
        self.output_filename = os.path.basename(filename) + "_obfuscated"
        try:
            self.binary = lief.ELF.parse(self.filename)
            if not self.binary:
                raise lief.bad_file(f"LIEF could not parse {filename}")
        except lief.bad_file as e:
            print(f"Error parsing ELF file: {e}")
            sys.exit(1)
        self.encryptions = [encrypt_xor, encrypt_rsa]

    def obfuscate(self, option, key=None):
        print(f"[+] Starting obfuscation for '{self.filename}'")
        raw = open(self.filename, 'rb').read()
        enc, key = self.encryptions[option-1](raw) 

        func_sign = {
            1 : f'decrypt_xor(elf_bytes, elf_len, {key[0]})',
            2 : f'decrypt_rsa(elf_bytes, elf_len, {key[0]}, {key[1]})'
        }
        c_code = f'''#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>

{xor_dec_func}
{rsa_dec_func}

size_t elf_len = {len(enc)};

static unsigned char elf_bytes[] = {bytes_to_c_array(enc)};

int main() {{
    {func_sign[option]};

    char tmpl[] = "/tmp/genelfXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) {{
        perror("mkstemp");
        return 4;
    }}
    size_t written = 0;
    while (written < elf_len) {{
        ssize_t w = write(fd, elf_bytes + written, elf_len - written);
        if (w < 0) {{
            if (errno == EINTR) continue;
            perror("write");
            close(fd);
            unlink(tmpl);
            return 5;
        }}
        written += (size_t)w;
    }}

    /* flush & close */
    if (fsync(fd) == -1) {{
        /* not fatal, but warn */
        perror("fsync");
    }}
    if (close(fd) == -1) {{
        perror("close");
        unlink(tmpl);
        return 6;
    }}

    /* make executable for owner only */
    if (chmod(tmpl, S_IRWXU) == -1) {{
        perror("chmod");
        unlink(tmpl);
        return 7;
    }}

    /* fork and exec */
    pid_t pid = fork();
    if (pid < 0) {{
        perror("fork");
        unlink(tmpl);
        return 8;
    }}

    if (pid == 0) {{
        /* Child: exec the newly created file.
           Use absolute path in argv[0] to be safe. */
        char *const argv[] = {{ tmpl, NULL }};
        execv(tmpl, argv);
        /* If execv returns, it failed */
        perror("execv");
        _exit(127);
    }} else {{
        /* Parent: wait for child */
        int status = 0;
        if (waitpid(pid, &status, 0) == -1) {{
            perror("waitpid");
            /* attempt cleanup */
            if (unlink(tmpl) == -1) perror("unlink");
            return 9;
        }}
    

        /* remove the file */
        if (unlink(tmpl) == -1) {{
            perror("unlink");
            return 10;
        }} else {{
    
        }}
    }}
    return 0;
}}
'''
        success, stdout, stderr, op = compile_c_string(c_code, 'main_obfs', 'gcc', ['-O3', '-s'])
        
        print("--- Compilation Result ---")
        print(f"Success: {success}")
        print(f"STDOUT: {stdout}")
        print(f"STDERR: {stderr}")
        print(f"Output: {op}")
        print("--------------------------")
        
        

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <elf_binary>")
        sys.exit(1)
    # option 1 -> xor
    # option 2 -> rsa
    # obfuscate(option)
    obfuscator = Obfuscator(sys.argv[1])
    obfuscator.obfuscate(1)
