"""
Signature Analysis Pipeline - VM Bytecode, Opcodes, Crypto Constants
=====================================================================

Tools for analyzing client-side request signing algorithms (TikTok X-Bogus style).

Author: DeadMan Toolkit v5.3
"""

import re, json, base64
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

# Known signature algorithms
KNOWN_ALGORITHMS = {
    'XXTEA': {'delta': 0x9E3779B9, 'key_size': 128, 'block_size': 64},
    'AES_GCM': {'key_sizes': [128, 192, 256], 'nonce_size': 96},
    'HMAC_SHA256': {'output_size': 256},
    'MD5': {'init_a': 0x67452301, 'init_b': 0xEFCDAB89, 'init_c': 0x98BADCFE, 'init_d': 0x10325476}
}

# =============================================================================
# VM BYTECODE TRACER
# =============================================================================

class VMState(Enum):
    RUNNING = "running"; HALTED = "halted"; ERROR = "error"; BREAKPOINT = "breakpoint"

@dataclass
class VMRegister:
    index: int; value: Any = None; is_constant: bool = False; description: str = ""

@dataclass
class VMFrame:
    return_address: int; registers: Dict[int, Any] = field(default_factory=dict); finally_flag: bool = False

@dataclass
class VMSnapshot:
    program_counter: int; registers: Dict[int, VMRegister]; call_stack: List[VMFrame]; opcode: int; operands: List[int]

class BytecodeTracer:
    VM_PATTERNS = {
        'switch_dispatcher': r'switch\s*\([a-zA-Z_$][\w$]*\s*>>>\s*\d+\s*&\s*\d+\)',
        'opcode_handler': r'case\s+(\d+)\s*:', 'register_array': r'([a-zA-Z_$][\w$]*)\s*\[\s*(\d+)\s*\]',
        'program_counter': r'([a-zA-Z_$][\w$]*)\s*\+=\s*(\d+)', 'bytecode_read': r'([a-zA-Z_$][\w$]*)\s*\[\s*([a-zA-Z_$][\w$]*)\s*\+\+\s*\]'
    }
    STANDARD_REGISTERS = {0: VMRegister(0, None, True, "null"), 1: VMRegister(1, None, True, "undefined"),
        2: VMRegister(2, True, True, "true"), 3: VMRegister(3, False, True, "false"),
        4: VMRegister(4, None, False, "return"), 5: VMRegister(5, None, False, "this"), 6: VMRegister(6, None, False, "arguments")}

    def __init__(self):
        self.bytecode, self.program_counter, self.state = b'', 0, VMState.HALTED
        self.registers = dict(self.STANDARD_REGISTERS)
        self.call_stack, self.exception_stack, self.breakpoints = [], [], set()
        self.opcode_handlers, self.trace_log, self.modules = {}, [], {}

    def load_bytecode(self, js_content: str) -> bool:
        for match in re.findall(r'"([A-Za-z0-9+/=]{100,})"', js_content):
            try:
                decoded = base64.b64decode(match)
                if len(decoded) >= 100 and sum(1 for b in decoded[:1000] if b < 128) > len(decoded[:1000]) * 0.3:
                    self.bytecode = decoded; return True
            except (ValueError, base64.binascii.Error): continue
        return False

    def extract_opcode_handlers(self, js_content: str) -> Dict[int, str]:
        handlers = {}
        for opcode_str, handler_code in re.findall(r'case\s+(\d+)\s*:\s*([^;]+;)', js_content):
            handlers[int(opcode_str)] = self._classify_handler(handler_code)
        self.opcode_handlers = handlers; return handlers

    def _classify_handler(self, code: str) -> str:
        c = code.lower()
        if any(op in c for op in ['>>>', '<<', '&', '|']): return 'BITWISE'
        if any(op in c for op in ['+', '-', '*', '/', '%']): return 'ARITHMETIC'
        if any(op in code for op in ['===', '!==', '==', '!=', '<', '>']): return 'COMPARISON'
        if 'call' in c or '(' in code: return 'CALL_RETURN' if 'return' in c else 'CALL'
        if 'new ' in c: return 'NEW_OBJECT'
        if 'throw' in c: return 'THROW'
        if 'return' in c: return 'RETURN'
        return 'COMPLEX'

    def find_module_entries(self, js_content: str) -> Dict[int, int]:
        modules = {}
        for addr in re.findall(r'N\s*\(\s*(\d+)\s*,', js_content):
            a = int(addr)
            if a > 1000: modules[len(modules)] = a
        for mod in re.findall(r'o\s*\[\s*(\d+)\s*\]\s*\.v\s*=', js_content):
            m = int(mod)
            if m > 700: modules[m] = 0
        self.modules = modules; return modules

    def step(self) -> bool:
        if not self.bytecode or self.program_counter >= len(self.bytecode): self.state = VMState.HALTED; return False
        if self.program_counter in self.breakpoints: self.state = VMState.BREAKPOINT; return False
        opcode = self.bytecode[self.program_counter]
        self.trace_log.append(VMSnapshot(self.program_counter, dict(self.registers), list(self.call_stack), opcode,
            [self.bytecode[self.program_counter + i] for i in range(1, 3) if self.program_counter + i < len(self.bytecode)]))
        self.program_counter += 1; self.state = VMState.RUNNING; return True

    def get_trace_summary(self) -> Dict[str, Any]:
        oc = defaultdict(int)
        for s in self.trace_log: oc[self.opcode_handlers.get(s.opcode, 'UNKNOWN')] += 1
        return {'total_instructions': len(self.trace_log), 'unique_opcodes': len(set(s.opcode for s in self.trace_log)),
            'opcode_distribution': dict(oc), 'modules_called': list(self.modules.keys())}

# =============================================================================
# OPCODE MAPPER
# =============================================================================

@dataclass
class OpcodeInfo:
    opcode: int; category: str; handler_code: str; operand_count: int; description: str; frequency: int = 0

class OpcodeMapper:
    CATEGORY_PATTERNS = {
        'ARITHMETIC': [(r'\+(?!=)', 'add'), (r'-(?!=)', 'sub'), (r'\*(?!=)', 'mul'), (r'/(?!=)', 'div')],
        'BITWISE': [(r'>>>', 'ushr'), (r'>>', 'shr'), (r'<<', 'shl'), (r'&(?!&)', 'and'), (r'\|(?!\|)', 'or'), (r'\^', 'xor')],
        'COMPARISON': [(r'===', 'seq'), (r'!==', 'sne'), (r'<=', 'le'), (r'>=', 'ge'), (r'<(?!=)', 'lt'), (r'>(?!=)', 'gt')],
        'JUMP': [(r'\.C\s*=', 'setpc')], 'CONDITIONAL_JUMP': [(r'if\s*\(', 'cond')],
        'CALL': [(r'\.call\(', 'call'), (r'\.apply\(', 'apply')], 'RETURN': [(r'return\s+', 'ret')], 'THROW': [(r'throw\s+', 'throw')]
    }

    def __init__(self): self.opcodes, self.categories, self.unknown_opcodes = {}, defaultdict(list), set()

    def analyze(self, js_content: str) -> Dict[str, int]:
        for switch_body in re.findall(r'switch\s*\([^)]+\)\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}', js_content, re.DOTALL):
            for opcode_str, handler in re.findall(r'case\s+(\d+)\s*:\s*((?:(?!case\s+\d+\s*:)[\s\S])*?)(?=case\s+\d+\s*:|$)', switch_body):
                op, cat = int(opcode_str), self._categorize(handler)
                self.opcodes[op] = OpcodeInfo(op, cat, handler.strip(), self._count_operands(handler), f"{cat.lower()} op")
                self.categories[cat].append(op)
                if cat == 'UNKNOWN': self.unknown_opcodes.add(op)
        return {c: len(ops) for c, ops in self.categories.items()}

    def _categorize(self, code: str) -> str:
        scores = defaultdict(int)
        for cat, patterns in self.CATEGORY_PATTERNS.items():
            for p, _ in patterns:
                if re.search(p, code): scores[cat] += 1
        return max(scores.items(), key=lambda x: x[1])[0] if scores else 'UNKNOWN'

    def _count_operands(self, code: str) -> int:
        return sum(len(re.findall(p, code)) for p in [r'j\s*\(\s*\w+\s*\)', r'B\s*\(\s*\w+\s*\)', r'x\s*\(\s*\w+\s*\)'])

    def get_summary(self) -> Dict[str, Any]:
        return {'total_opcodes': len(self.opcodes), 'categories': {c: len(o) for c, o in self.categories.items()}, 'unknown_count': len(self.unknown_opcodes)}

# =============================================================================
# CRYPTO CONSTANT FINDER
# =============================================================================

@dataclass
class CryptoConstant:
    name: str; value: int; hex_value: str; algorithm: str; confidence: float; context: str

class CryptoConstantFinder:
    KNOWN_CONSTANTS = {
        0x9E3779B9: ('TEA_DELTA', 'TEA/XXTEA', 'Golden ratio'), 0x61C88647: ('TEA_DELTA_NEG', 'TEA/XXTEA', 'Neg delta'),
        0x67452301: ('MD5_A/SHA1_H0', 'MD5/SHA-1', 'Init A/H0'), 0xEFCDAB89: ('MD5_B/SHA1_H1', 'MD5/SHA-1', 'Init B/H1'),
        0x98BADCFE: ('MD5_C/SHA1_H2', 'MD5/SHA-1', 'Init C/H2'), 0x10325476: ('MD5_D/SHA1_H3', 'MD5/SHA-1', 'Init D/H3'),
        0xC3D2E1F0: ('SHA1_H4', 'SHA-1', 'SHA-1 H4'),
        0x6A09E667: ('SHA256_H0', 'SHA-256', 'H0'), 0xBB67AE85: ('SHA256_H1', 'SHA-256', 'H1'),
        0xEDB88320: ('CRC32_POLY', 'CRC-32', 'Reversed poly'), 0xDEADBEEF: ('HASH_SEED', 'Custom', 'TikTok seed'),
        0x5BD1E995: ('MURMUR2_M', 'MurmurHash2', 'Multiplier'), 0x811C9DC5: ('FNV1_32_INIT', 'FNV-1', 'Offset basis'),
    }
    HASH_MULTIPLIERS = {65599: 'SDBM', 33: 'DJB2', 31: 'Java String', 5381: 'DJB2 init'}

    def __init__(self): self.found_constants = []

    def scan(self, js_content: str) -> List[CryptoConstant]:
        self.found_constants = []
        for match in re.finditer(r'0x([0-9A-Fa-f]{4,8})\b', js_content):
            h, v = match.group(1), int(match.group(1), 16)
            ctx = js_content[max(0, match.start()-50):min(len(js_content), match.start()+50)]
            if v in self.KNOWN_CONSTANTS:
                n, a, d = self.KNOWN_CONSTANTS[v]
                self.found_constants.append(CryptoConstant(n, v, f"0x{h.upper()}", a, 1.0, ctx))
            elif len(h) == 8 and len(set(int(h[i:i+2], 16) for i in range(0, 8, 2))) >= 3:
                self.found_constants.append(CryptoConstant(f"UNKNOWN_{h.upper()}", v, f"0x{h.upper()}", "Unknown", 0.5, ctx))
        for mult, desc in self.HASH_MULTIPLIERS.items():
            if re.search(rf'\*\s*{mult}\b', js_content):
                self.found_constants.append(CryptoConstant(f"HASH_MULT_{mult}", mult, f"0x{mult:X}", "Hash", 0.8, desc))
        seen = set(); self.found_constants = [c for c in self.found_constants if c.value not in seen and not seen.add(c.value)]
        return self.found_constants

    def identify_algorithm(self) -> Optional[str]:
        algs = defaultdict(int)
        for c in self.found_constants:
            if c.algorithm != "Unknown": algs[c.algorithm] += 1
        return max(algs.items(), key=lambda x: x[1])[0] if algs else None

    def get_summary(self) -> Dict: return {'total': len(self.found_constants), 'algorithm': self.identify_algorithm(),
        'by_algorithm': {a: [{'name': c.name, 'value': c.hex_value} for c in self.found_constants if c.algorithm == a]
            for a in set(c.algorithm for c in self.found_constants)}}

# =============================================================================
# SIGNATURE ANALYZER (High-level)
# =============================================================================

@dataclass
class SignatureAnalysisResult:
    has_vm_protection: bool; algorithm: Optional[str]; opcode_count: int; opcode_categories: Dict[str, int]
    crypto_constants: List[Dict]; modules: Dict[int, int]; entry_points: List[int]; complexity_score: float; recommendations: List[str]

class SignatureAnalyzer:
    def __init__(self, filepath: Optional[str] = None, content: Optional[str] = None):
        if filepath:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f: self.content = f.read()
            except: self.content = ""
            self.filepath = filepath
        else: self.content, self.filepath = content or "", None
        self.tracer, self.mapper, self.finder, self.result = BytecodeTracer(), OpcodeMapper(), CryptoConstantFinder(), None

    def analyze(self) -> SignatureAnalysisResult:
        if not self.content: return SignatureAnalysisResult(False, None, 0, {}, [], {}, [], 0.0, ["No content"])
        has_bc = self.tracer.load_bytecode(self.content)
        handlers = self.tracer.extract_opcode_handlers(self.content)
        has_vm = has_bc or bool(handlers)
        cats = self.mapper.analyze(self.content)
        summary = self.mapper.get_summary()
        consts = self.finder.scan(self.content)
        algo = self.finder.identify_algorithm()
        modules = self.tracer.find_module_entries(self.content)
        score = min(10.0, (3.0 if has_vm else 0) + (2.0 if summary['total_opcodes'] > 100 else 1.0 if summary['total_opcodes'] > 50 else 0.5 if summary['total_opcodes'] > 0 else 0) +
            (2.0 if len(consts) > 5 else 1.0 if len(consts) > 2 else 0.5 if consts else 0) + (2.0 if len(modules) > 5 else 1.0 if len(modules) > 2 else 0.5 if modules else 0))
        recs = []
        if has_vm: recs.append("VM-protected code detected - use dynamic analysis")
        if algo: recs.append(f"{algo} detected - focus on key derivation")
        if summary.get('unknown_count', 0) > 10: recs.append(f"{summary['unknown_count']} unknown opcodes - manual analysis needed")
        self.result = SignatureAnalysisResult(has_vm, algo, summary['total_opcodes'], cats,
            [{'name': c.name, 'hex': c.hex_value, 'algorithm': c.algorithm} for c in consts], modules, list(modules.values()), score, recs)
        return self.result

    def export_report(self, filepath: str):
        if not self.result: self.analyze()
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump({'has_vm': self.result.has_vm_protection, 'algorithm': self.result.algorithm, 'complexity': self.result.complexity_score,
                'opcodes': self.result.opcode_count, 'crypto_constants': self.result.crypto_constants, 'recommendations': self.result.recommendations}, f, indent=2)

def analyze_vm_structure(js_content: str) -> Dict[str, Any]:
    t = BytecodeTracer()
    return {'has_bytecode': t.load_bytecode(js_content), 'opcode_handlers': t.extract_opcode_handlers(js_content),
        'modules': t.find_module_entries(js_content), 'vm_patterns': {n: bool(re.search(p, js_content)) for n, p in BytecodeTracer.VM_PATTERNS.items()}}

__all__ = ['BytecodeTracer', 'OpcodeMapper', 'CryptoConstantFinder', 'SignatureAnalyzer', 'SignatureAnalysisResult', 'VMState', 'VMSnapshot', 'OpcodeInfo', 'CryptoConstant', 'analyze_vm_structure', 'KNOWN_ALGORITHMS']
