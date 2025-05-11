#!/usr/bin/env python3

import os
import shutil
from subprocess import Popen, PIPE
import re
import time
import random
from functools import reduce
from enum import Enum
from typing import Optional, List, Set
from threading import BoundedSemaphore, Timer

from word import Tpe_map


class TPE(Enum):
    NONE  = 0
    BR    = 1
    XCPT  = 2
    FLUSH = 3


GEN_CNT = 1000
PFX     = 'pfx'
PRP     = 'prp'
FUNC    = 'fn'
TC      = 'tc'
TSX     = 'tsx'
RCV     = 'rcv'


class RollBackInfo:
    def __init__(self, tpe: str, opcode: str, cause: str):
        self.tpe = tpe
        self.opcode = opcode
        self.cause = cause

    def __eq__(self, o: 'RollBackInfo'):
        ret = ((self.tpe == o.tpe) and
               (Tpe_map[self.opcode] == Tpe_map[o.opcode]) and
               (self.cause == o.cause))
        return ret

    def __str__(self):
        return f'{self.tpe}_{self.opcode}_{self.cause}'

    def __hash__(self):
        return hash(self.tpe) ^ hash(Tpe_map[self.opcode]) ^ hash(self.cause)


class Component:
    def __init__(self, mod: str, mid: int, mem: str):
        self.mod = mod
        self.mid = mid
        self.mem = mem

    def __eq__(self, o: 'Component'):
        ret = ((self.mod == o.mod) and
               (self.mid == o.mid) and
               (self.mem == o.mem))
        return ret

    def __hash__(self):
        return hash(self.mod) ^ hash(self.mid) ^ hash(self.mem)

    def __str__(self):
        return f'{self.mod}({self.mid}): {self.mem}'


class ROBLog:
    def __init__(self, tpe: int, tpc: int, mpc: int, trg_inst: int, ewsz: int):
        self.tpe = TPE(tpe).name
        self.tpc = tpc
        self.mpc = mpc
        self.trg_inst = os.popen('echo "DASM({0:08x})" | spike-dasm'
                                 .format(trg_inst)).read()
        self.trg_opcode = self.trg_inst.replace('\n', '').split(' ')[0]
        self.ewsz = ewsz

        self.str = f'{self.tpe}_{hex(tpc)}_{hex(mpc)}_{self.trg_opcode}_{ewsz}'

    def __str__(self):
        return self.str


class Preprocessor:
    def __init__(self, target: str, output: str, dsize=1024):
        self.target = target
        # Convert output path to absolute path
        self.output = os.path.abspath(output)
        
        # Get the absolute path of the Template directory
        fuzzer_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.template = os.path.join(fuzzer_dir, 'Template')
        
        print(f'[DEBUG] Initializing Preprocessor:')
        print(f'[DEBUG] Target: {self.target}')
        print(f'[DEBUG] Output directory: {self.output}')
        print(f'[DEBUG] Template directory: {self.template}')
        
        # Ensure directories exist
        os.makedirs(self.output, exist_ok=True)
        if not os.path.exists(self.template):
            raise FileNotFoundError(f'Template directory not found: {self.template}')

        self.rand = random.Random()
        self.randLock = BoundedSemaphore(1)

        assert dsize % 16 == 0, f'Invalid dsize: {dsize}'
        self.dsize = dsize

    def embed_attack(self, pfx: str, prps: List[str], funcs: str,
                     asm: str, ent: int, tid: int) -> str:
        # Ensure output directory exists
        os.makedirs(self.output, exist_ok=True)
        
        ret = f'{self.output}/.t1_input_{tid}'
        template_file = os.path.join(self.template, 'entry.S')
        
        print(f'[DEBUG] Creating file: {ret}.S')
        print(f'[DEBUG] Using template: {template_file}')
        
        # Check if template file exists
        if not os.path.exists(template_file):
            raise FileNotFoundError(f'Template file not found: {template_file}')

        self.randLock.acquire()
        self.rand.seed(ent)
        
        try:
            with open(template_file, 'r') as fd:
                lines = fd.readlines()

            with open(f'{ret}.S', 'w') as fd:
                for line in lines:
                    fd.write(line)

                    if re.match('^prefix:.*', line):
                        fd.write(pfx)
                    elif re.match('^pre_attack[0-9]+:.*', line):
                        prp = prps.pop(0)
                        fd.write(prp)
                    elif re.match('^shared:.*', line):
                        fd.write(funcs)
                    elif re.match('^attack:.*', line):
                        fd.write(asm)
                    elif re.search('^data[0-9]+:.*', line):
                        for i in range(self.dsize // (8 * 2)):
                            r0 = self.rand.randint(0, 0xffffffffffffffff)
                            r1 = self.rand.randint(0, 0xffffffffffffffff)
                            fd.write(f'    .dword {hex(r0)}, {hex(r1)}\n')

            print(f'[DEBUG] Successfully created file: {ret}.S')
        except Exception as e:
            print(f'[ERROR] Failed to create assembly file: {str(e)}')
            raise e
        finally:
            self.rand.seed(time.time())
            self.randLock.release()

        return ret

    def embed_tsx(self, prg: str, tpc: int, cpc: int,
                 mpc: int, tpe: TPE) -> (bool, str):

        syms = os.popen(f'nm {prg}.riscv | grep "tc."').read().split('\n')[:-1]
        sMap = {i[2]: int(i[0], 16)
                for i in [j.split(' ') for j in syms]}

        symbolMap = {v: k for k, v in sMap.items()
                     if re.match('^l[0-9]+', k[-2:])}

        def embed_str(lines: List[str], label: str, s: str):
            try:
                idx = [i for i, l in enumerate(lines) if
                       re.match(f'^{label}:.*', l)][0]
                lines.insert(idx, s)
            except:
                raise Exception(f'{label} not in asm')

        tl = symbolMap[max([i for i in symbolMap.keys() if i <= mpc])]

        ml = symbolMap.get(mpc, None)
        cl = symbolMap.get(cpc, None)

        # Filter out misaligned accesses
        if ml and ((tpe != TPE.BR) or (cl and ml != cl)):
            with open(f'{prg}.S', 'r') as fd:
                asm = fd.readlines()

            if ml == cl:
                # TODO: Support data-flow misprediction
                if self.target == 'Nutshell':
                    print(f'[SpecDoctor] Does not support data-flow misprediction')
                    os.makedirs(f'{self.output}/dataflow', exist_ok=True)
                    name = prg.split('/')[-1]
                    shutil.move(f'{prg}.S', f'{self.output}/dataflow/{name}.S')
                    return False, ''

                embed_str(asm, ml,
                          f'{"" :<20}spdoc_check_d\ntransient:\ntransient_end:\n')
            elif tpe == TPE.BR:
                embed_str(asm, ml, 'transient:\ntransient_end:\n')
                embed_str(asm, cl, f'{"" :<20}spdoc_check_c\n')
            else:
                embed_str(asm, ml, 'transient:\ntransient_end:\n')

            with open(f'{prg}.S', 'w') as fd:
                fd.write(''.join(asm))

            return True, tl
        else:
            return False, ''

    def embed_sec(self, tid: int, tprg: str, asm: str, sd: int, tid2: int) -> str:
        # Ensure output directory exists
        os.makedirs(self.output, exist_ok=True)
        
        # Extract base name without extension
        base = os.path.splitext(tprg)[0]
        ret = f'{self.output}/.t{tid}_input_{tid2}'
        
        # Use entry.S as the template file
        template_file = os.path.join(self.template, 'entry.S')
        
        print(f'[DEBUG] Creating file: {ret}.S')
        print(f'[DEBUG] Using template: {template_file}')
        
        # Check if template file exists
        if not os.path.exists(template_file):
            raise FileNotFoundError(f'Template file not found: {template_file}')

        # Copy template file with .S extension
        shutil.copyfile(template_file, f'{ret}.S')

        with open(f'{ret}.S', 'r') as fd:
            lines = fd.readlines()

        # Ensure encoding.h is included at the top
        if not any('#include "encoding.h"' in line for line in lines):
            lines.insert(0, '#include "encoding.h"\n\n')

        # Find the insertion point for the assembly code
        for i, line in enumerate(lines):
            if re.match('^transient:.*', line):
                lines[i] = asm
                break

        # Write the modified assembly with both .S and .du.S extensions
        with open(f'{ret}.S', 'w') as fd:
            fd.write(''.join(lines))
            
        with open(f'{ret}.du.S', 'w') as fd:
            fd.write(''.join(lines))

        print(f'[DEBUG] Successfully created files: {ret}.S and {ret}.du.S')
        return ret

    def extract_block(self, prg: str, name: str) -> str:
        # Try both .S and .du.S extensions
        extensions = ['.S', '.du.S']
        found = False
        
        for ext in extensions:
            path = f'{prg}{ext}'
            if os.path.exists(path):
                found = True
                break
                
        if not found:
            raise FileNotFoundError(f'Neither {prg}.S nor {prg}.du.S exists')

        with open(path, 'r') as fd:
            lines = fd.readlines()

        ret = []
        scope = 'NONE'
        for line in lines:
            if scope == 'NONE':
                if re.match(f'^{name}:.*', line):
                    ret.append(line)
                    scope = 'BLOCK'
            elif scope == 'BLOCK':
                if re.match('^[a-zA-Z].*:.*', line):
                    if not re.match(f'^{name}\..*:.*', line):
                        break
                ret.append(line)

        return ''.join(ret)

    def compile(self, prg: str, atk: str, com: str, ent: int,
                isa=0, spdoc=0) -> Optional[str]:
        # Convert paths to relative paths from Template directory
        rel_prg = os.path.relpath(prg, self.template)
        
        # First check if all required files and directories exist
        inc_dir = os.path.join(self.template, 'inc')
        src_dir = os.path.join(self.template, 'src')
        link_dir = os.path.join(self.template, 'link')
        source_file = f'{prg}.S'
        
        try:
            print(f'[DEBUG] Checking required paths:')
            print(f'  Template dir: {self.template}')
            print(f'  Include dir: {inc_dir}')
            print(f'  Source dir: {src_dir}')
            print(f'  Link dir: {link_dir}')
            print(f'  Source file: {source_file}')
            
            for path in [self.template, inc_dir, src_dir, link_dir, source_file]:
                if not os.path.exists(path):
                    print(f'[ERROR] Required path does not exist: {path}')
                    return None
            
            # Check source file content
            try:
                with open(source_file, 'r') as f:
                    content = f.read(1000)  # Only read first 1000 chars
                    print(f'[DEBUG] Source file preview:\n{content[:200]}...')
            except Exception as e:
                print(f'[ERROR] Failed to read source file: {str(e)}')
                return None
            
            # Get list of source files
            src_files = ' '.join([os.path.join(src_dir, f) for f in os.listdir(src_dir) if f.endswith('.c')])
            
            # Check linker script
            linker_script = os.path.join(link_dir, 'link.ld')
            try:
                with open(linker_script, 'r') as f:
                    linker_content = f.read()
                    print(f'[DEBUG] Linker script preview:\n{linker_content[:200]}...')
            except Exception as e:
                print(f'[ERROR] Failed to read linker script: {str(e)}')
                return None
            
            # Construct make command with explicit flags
            flag = f'-C {self.template}'
            cmd = f'make PROGRAM={rel_prg} ' + \
                  f'TARGET={self.target} ' + \
                  f'ATTACK={atk} COMMIT={com} ENTROPY={ent} ' + \
                  f'ISA={isa} ' + \
                  f'SPDOC={spdoc} ' + \
                  f'CFLAGS="-mcmodel=medany -ffreestanding -fvisibility=hidden -fno-zero-initialized-in-bss -march=rv64g -mabi=lp64 -std=gnu99 -O0 -g" ' + \
                  f'LDFLAGS="-static -nostdlib -nostartfiles -Wl,--build-id=none" ' + \
                  f'{flag}'
            
            print(f'[DEBUG] Running compilation command: {cmd}')
            print(f'[DEBUG] Current working directory: {os.getcwd()}')
            
            # Run make with detailed output
            compile_output = os.popen(cmd + ' 2>&1').read()
            print(f'[DEBUG] Compilation output:\n{compile_output[:1000]}')  # Limit output size

            binary = f'{prg}.riscv'
            image = f'{prg}.bin' # Needed for Nutshell

            if os.path.isfile(binary):
                if self.target == 'Nutshell' and not os.path.isfile(image):
                    print(f'[ERROR] Image file not found for Nutshell: {image}')
                    return None
                    
                # Check binary size and validity
                binary_size = os.path.getsize(binary)
                print(f'[DEBUG] Binary size: {binary_size} bytes')
                
                # Check ELF validity
                readelf_cmd = f'riscv64-unknown-elf-readelf -h {binary}'
                readelf_output = os.popen(readelf_cmd).read()
                if 'ELF64' not in readelf_output:
                    print(f'[ERROR] Invalid ELF file generated')
                    return None
                    
                print(f'[DEBUG] Successfully generated binary: {binary}')
                return binary
            else:
                print(f'[ERROR] Binary file not generated: {binary}')
                
                # Try direct compilation for more error info
                gcc_cmd = (f'riscv64-unknown-elf-gcc -v '
                          f'-mcmodel=medany -ffreestanding -fvisibility=hidden '
                          f'-fno-zero-initialized-in-bss -march=rv64g -mabi=lp64 '
                          f'-std=gnu99 -O0 -g -static -nostdlib -nostartfiles '
                          f'-Wl,--build-id=none '  # Avoid build ID section
                          f'-I{inc_dir} -T{link_dir}/link.ld '
                          f'{source_file} {src_files} -o {binary} 2>&1')
                print(f'[DEBUG] Trying direct compilation: {gcc_cmd}')
                try:
                    error_output = os.popen(gcc_cmd).read()
                    print(f'[DEBUG] Direct compilation output:\n{error_output[:1000]}')  # Limit output size
                except IOError as e:
                    print(f'[ERROR] Failed to capture compilation output: {str(e)}')
                
                # Also try preprocessing only
                preproc_cmd = f'riscv64-unknown-elf-gcc -E -I{inc_dir} {source_file} 2>&1'
                print(f'[DEBUG] Trying preprocessing: {preproc_cmd}')
                try:
                    preproc_output = os.popen(preproc_cmd).read()
                    print(f'[DEBUG] Preprocessing output:\n{preproc_output[:1000]}')  # Limit output size
                except IOError as e:
                    print(f'[ERROR] Failed to capture preprocessing output: {str(e)}')
                
                return None
                
        except IOError as e:
            print(f'[ERROR] IO error during compilation: {str(e)}')
            return None
        except Exception as e:
            print(f'[ERROR] Unexpected error during compilation: {str(e)}')
            return None

    def clean(self, prg: str):
        flag = f'-C {self.template}'
        mute = '> /dev/null 2>&1'
        os.system(f'make PROGRAM=$PWD/{prg} clean ' +
                  f'{flag} {mute}')


class Simulator:
    def __init__(self, target: str, rsim: str, isim: str):
        self.target = target
        self.rsim = rsim
        self.isim = isim

    def runRTL(self, binary: str, log: str, recv=False, debug=False) -> int:
        timing = '-t' if recv else ''

        print(f'[DEBUG] Validating binary: {binary}')
        
        # Check if simulator exists
        if not os.path.exists(self.rsim):
            print(f'[ERROR] RTL simulator not found: {self.rsim}')
            return -1
            
        # Check if binary exists and is valid
        if not os.path.exists(binary):
            print(f'[ERROR] Binary not found: {binary}')
            return -1
            
        # Get file size
        binary_size = os.path.getsize(binary)
        print(f'[DEBUG] Binary file size: {binary_size} bytes')
        
        # Check ELF file validity
        try:
            # Check ELF header
            readelf_cmd = f'riscv64-unknown-elf-readelf -h {binary}'
            readelf_output = os.popen(readelf_cmd).read()
            print(f'[DEBUG] ELF header info:\n{readelf_output}')
            
            # Check program headers
            readelf_cmd = f'riscv64-unknown-elf-readelf -l {binary}'
            readelf_output = os.popen(readelf_cmd).read()
            print(f'[DEBUG] Program headers:\n{readelf_output}')
            
            # Parse program headers to check sizes
            if 'LOAD' not in readelf_output:
                print(f'[ERROR] No loadable segments found in binary')
                return -1
                
            # Extract segment info using objdump
            objdump_cmd = f'riscv64-unknown-elf-objdump -h {binary}'
            objdump_output = os.popen(objdump_cmd).read()
            print(f'[DEBUG] Section headers:\n{objdump_output}')
            
            # Check for common issues
            if binary_size < 1024:  # Suspiciously small
                print(f'[WARNING] Binary file seems too small: {binary_size} bytes')
            
            # Try to fix alignment if needed
            objcopy_cmd = f'riscv64-unknown-elf-objcopy --set-section-alignment .text=16 {binary} {binary}.aligned'
            os.system(objcopy_cmd)
            if os.path.exists(f'{binary}.aligned'):
                print(f'[DEBUG] Created aligned binary: {binary}.aligned')
                binary = f'{binary}.aligned'
            
        except Exception as e:
            print(f'[ERROR] Failed to check ELF file: {str(e)}')
            return -1

        # Construct RTL simulation command
        if self.target == 'Boom':
            debug = f'-x 70000 --vcd={log.rsplit(".", 1)[0]}.vcd' if debug else '' # TODO: 70000?
            cmd = f'{self.rsim} --seed=0 --verbose {timing} {debug} {binary}'
        elif self.target == 'Nutshell':
            image = binary.split('.riscv')[0] + '.bin'
            debug = f'-d {log.rsplit(".", 1)[0]}.vcd' if debug else ''
            cmd = f'{self.rsim} -s 0 -b 0 -e 0 {timing} {debug} -i {image}'

        print(f'[DEBUG] Running RTL simulation command: {cmd}')
        print(f'[DEBUG] Current working directory: {os.getcwd()}')

        try:
            p = Popen([i for i in cmd.split(' ') if i != ''],
                    stderr=PIPE, stdout=PIPE)
            timer = Timer(600, p.kill)
            try:
                timer.start()
                stdout, stderr = p.communicate()
                stdout_str = stdout.decode('utf-8')
                stderr_str = stderr.decode('utf-8')
                print(f'[DEBUG] RTL simulation stdout:\n{stdout_str[:1000]}')  # Limit output size
                print(f'[DEBUG] RTL simulation stderr:\n{stderr_str[:1000]}')  # Limit output size
            finally:
                timer.cancel()

            with open(log, 'w') as fd:
                fd.write(stderr_str)

            ret = p.poll()
            print(f'[DEBUG] RTL simulation return code: {ret}')
            
            # Clean up aligned binary if it was created
            if os.path.exists(f'{binary}.aligned'):
                os.remove(f'{binary}.aligned')
                
            return ret
            
        except Exception as e:
            print(f'[ERROR] Failed to run RTL simulation: {str(e)}')
            return -1

    # Run ISA simulation to obtain cause message
    def runISA(self, binary: str) -> str:
        ret = os.popen(f'{self.isim} -l {binary} 2>&1').read()
        return ret


class Analyzer:
    def __init__(self, target: str):
        self.target = target

    def analyze_t1(self, binary: str, log: str) -> (bool, Optional[ROBLog]):
        symbols = os.popen(f'nm {binary} | grep " attack"').read().split('\n')
        start = int(symbols[0].split()[0], 16)
        end = int(symbols[1].split()[0], 16)

        with open(f'{log}', 'r') as fd:
            lines = fd.readlines()

        if 'PASSED' not in lines[-1]:
            return (False, None)

        lines = lines[3:-1]
        res = ROBLog(0, 0, 0, 0, 0)
        pattern = '^([0-9]) \((.*)\) -> \((.*)\) DASM\((.*)\) \[(.*)\]\[(.*)\]'
        enc = [10, 16, 16, 16, 10, 10]
        for line in lines:
            match = re.search(pattern, line)
            tpe, tpc, mpc, trg_inst, wsz, ewsz = tuple([int(match.group(i), enc[i-1])
                                                       for i in range(1, 7)])

            if tpc >= start and tpc < end and ewsz > res.ewsz:
                # NOTE: mpc should be under 'attack' label for instruction embedding
                if tpe == TPE.BR.value:
                    if mpc > tpc and mpc < end:
                        res = ROBLog(tpe, tpc, mpc, trg_inst, ewsz)
                elif mpc >= start and mpc < end:
                    res = ROBLog(tpe, tpc, mpc, trg_inst, ewsz)

        if res.ewsz:
            return (True, res)
        else:
            return (False, None)

    def analyze_t3(self, logs: List[str]) -> (bool, Set[Component]):

        pattern = '^\[(.*)\((.*)\)]\((.*)\)=\[(.*)\]'
        logMaps = {}
        for i, log in enumerate(logs):
            with open(f'{log}', 'r') as fd:
                lines = fd.readlines()

            logMap = {}
            for line in lines:
                match = re.search(pattern, line)
                if not match: continue
                (mod, mid, mem, val) = tuple([match.group(i)
                                              for i in range(1, 5)])

                k = (mod, int(mid))
                v = (mem, int(val, 16))
                logMap[k] = logMap.get(k, []) + [v]

            for k, v in logMap.items():
                vals = [i[1] for i in v]
                logMap[k] = (reduce(lambda i, j: i^j, vals), v)

            logMaps[i] = logMap

        diffs = []
        # TODO: Must ensure all logMap items have same keys
        # For (mname, mid)
        for k in logMaps[0].keys():
            # First check, module level hash
            if len(set([m[k][0] for m in logMaps.values()])) != 1:

                def f(x: tuple): return x[0]
                names = list(map(f, set(sum([m[k][1]
                                             for m in logMaps.values()], []))))

                def g(x: str): return (names.count(x) > 1)
                diffs += [Component(k[0], k[1], i)
                          for i in list(set(filter(g, names)))]

        if diffs:
            return (True, set(diffs))
        else:
            return (False, {})

    def analyze_t4(self, logs: List[str]) -> bool:

        pattern = '.*\[SpecDoctor\] Cycle: ([0-9]+).*'

        cycles = []
        passed = True
        for i, log in enumerate(logs):
            with open(f'{log}', 'r') as fd:
                line = '\n'.join(fd.readlines())

            match = re.match(pattern, line, re.DOTALL)
            ###### TODO: Delete ########
            if not match:
                return False
            ############################
            cycles.append(int(match.group(1)))

            passed = passed and ('FAILED' not in line)

        return passed and (len(set(cycles)) > 1)
