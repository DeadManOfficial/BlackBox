# AMD Debugging Doctrine
## Memory, Coherency & Spec Compliance Methodology

**Source:** AMD Developer Guides, Memory Subsystem Engineering, Heterogeneous Computing

---

## Core Principles

### 1. Memory/Coherency First

**Definition:** When results are "almost correct" or non-deterministic, assume memory/coherency bug until proven otherwise.

**Memory Bug Symptoms:**
- Results differ between runs
- Results are "close" but not exact
- Failure depends on timing
- Works on one core, fails on multiple
- Corruption patterns in output

**Coherency Issues:**
| Symptom | Likely Cause |
|---------|--------------|
| Stale reads | Cache coherency |
| Lost writes | Write buffer |
| Torn reads | Alignment |
| Reordering | Memory barriers |
| Race conditions | Synchronization |

**Diagnostic Checklist:**
```python
def diagnose_memory_issue(failure):
    checks = [
        ("Alignment", check_alignment(failure.data)),
        ("Barriers", check_memory_barriers(failure.code)),
        ("Atomics", check_atomic_operations(failure.code)),
        ("Cache", check_cache_coherency(failure.state)),
        ("NUMA", check_numa_locality(failure.allocation)),
    ]

    for name, result in checks:
        if not result.ok:
            return f"MEMORY ISSUE: {name} - {result.detail}"

    return "Memory cleared - investigate other causes"
```

**Memory Debugging Tools:**
| Tool | Purpose |
|------|---------|
| Valgrind | Memory errors, leaks |
| AddressSanitizer | Out-of-bounds, use-after-free |
| ThreadSanitizer | Race conditions |
| MemorySanitizer | Uninitialized reads |
| UBSan | Undefined behavior |

**Rule:** IF results are "almost correct" OR non-deterministic → Assume MEMORY BUG until proven otherwise

---

### 2. Spec Compliance Primacy

**Definition:** If behavior contradicts specification, the code is wrong—not the hardware, not the runtime.

**Hierarchy of Truth:**
```
1. Specification (absolute truth)
   ↓
2. Reference Implementation
   ↓
3. Documentation
   ↓
4. Common Practice
   ↓
5. Developer Assumption (lowest authority)
```

**Spec Check Process:**
```python
def check_spec_compliance(behavior, spec):
    """
    Compare actual behavior against spec.
    Spec is always correct.
    """
    if behavior.contradicts(spec):
        return Verdict(
            result="CODE_IS_WRONG",
            reason="Behavior contradicts specification",
            spec_reference=spec.section,
            required_behavior=spec.expected,
            actual_behavior=behavior.observed
        )

    if behavior.is_undefined_by(spec):
        return Verdict(
            result="DEVELOPER_ERROR",
            reason="Relies on undefined behavior",
            spec_reference=spec.section,
            recommendation="Rewrite to use defined behavior"
        )

    return Verdict(result="COMPLIANT")
```

**Common Spec Violations:**
| Violation | Example | Consequence |
|-----------|---------|-------------|
| Type punning | Union for cast | Undefined |
| Signed overflow | INT_MAX + 1 | Undefined |
| Null dereference | *NULL | Undefined |
| Race condition | Unsync access | Undefined |
| Buffer overflow | arr[n+1] | Undefined |

**Rule:** IF behavior contradicts spec → CODE IS WRONG (not hardware, not runtime)
**Rule:** IF behavior is undefined by spec → DEVELOPER ERROR

---

### 3. Undefined Behavior Classification

**Definition:** Identify and eliminate reliance on undefined behavior.

**UB Categories:**
```
CATEGORY 1: Immediate Crash
├── Null pointer dereference
├── Division by zero
└── Stack overflow

CATEGORY 2: Silent Corruption
├── Buffer overflow
├── Use-after-free
├── Uninitialized memory
└── Type confusion

CATEGORY 3: Non-Deterministic
├── Race conditions
├── Memory ordering
├── Optimizer assumptions
└── Platform-specific behavior

CATEGORY 4: Works By Accident
├── Relying on memory layout
├── Assuming padding
├── Endianness assumptions
└── Compiler-specific extensions
```

**Detection Strategy:**
```bash
# Compile with all sanitizers
CFLAGS="-fsanitize=address,undefined,thread -fno-omit-frame-pointer"

# Run with sanitizer reporting
UBSAN_OPTIONS="print_stacktrace=1" ./program

# Static analysis
clang-tidy --checks='*' source.cpp
```

**Rule:** IF behavior relies on undefined spec → DEVELOPER ERROR → STOP

---

### 4. Heterogeneous System Debugging

**Definition:** Debug across CPU/GPU/FPGA boundaries systematically.

**Heterogeneous Stack:**
```
┌─────────────────────────────────────────┐
│           APPLICATION (Host)            │
├─────────────────────────────────────────┤
│     RUNTIME (ROCm, OpenCL, CUDA)        │
├─────────────┬─────────────┬─────────────┤
│    CPU      │     GPU     │    FPGA     │
├─────────────┼─────────────┼─────────────┤
│  x86 ISA    │   RDNA ISA  │   Bitstream │
├─────────────┴─────────────┴─────────────┤
│          MEMORY SUBSYSTEM               │
│    (Unified Memory, PCIe, Infinity)     │
└─────────────────────────────────────────┘
```

**Cross-Device Debugging:**
| Issue | CPU Side | GPU Side |
|-------|----------|----------|
| Data transfer | Verify send | Verify receive |
| Synchronization | Check fence | Check barrier |
| Memory | Check allocation | Check access |
| Computation | Validate input | Validate kernel |

**Boundary Debugging:**
```python
def debug_heterogeneous(workload):
    # Step 1: Isolate to device
    cpu_result = run_on_cpu_only(workload)
    gpu_result = run_on_gpu_only(workload)

    if cpu_result != gpu_result:
        # Computation difference
        return bisect_kernel(workload)

    # Step 2: Check transfers
    transfer_integrity = verify_transfer(workload.data)
    if not transfer_integrity:
        return "DATA TRANSFER CORRUPTION"

    # Step 3: Check synchronization
    sync_valid = verify_synchronization(workload)
    if not sync_valid:
        return "SYNCHRONIZATION FAILURE"

    return "ISSUE NOT ISOLATED"
```

---

## AMD Debugging Checklist

### Memory Phase
- [ ] Alignment verified
- [ ] Memory barriers present
- [ ] Atomic operations correct
- [ ] No data races
- [ ] Sanitizers run clean

### Spec Phase
- [ ] Behavior matches spec
- [ ] No undefined behavior
- [ ] No platform assumptions
- [ ] No compiler extensions
- [ ] Portable code

### Heterogeneous Phase
- [ ] CPU computation verified
- [ ] GPU computation verified
- [ ] Transfers verified
- [ ] Synchronization verified
- [ ] Memory coherency confirmed

### Validation Phase
- [ ] Test on multiple platforms
- [ ] Test on multiple compilers
- [ ] Test with optimizations
- [ ] Test without optimizations

---

## Integration with Bug Bounty

**Mapping:**
| AMD Concept | Bug Bounty Application |
|-------------|------------------------|
| Memory first | Check for memory corruption vulns |
| Spec compliance | Verify against API docs |
| Undefined behavior | Race conditions, type confusion |
| Heterogeneous | Client/server boundary bugs |

**Application:**
```
Vulnerability Analysis
├── Memory: Buffer overflow? Use-after-free?
├── Spec: Does behavior match documentation?
├── UB: Race condition? Type confusion?
└── Boundary: Client/server desync?
```

**Memory Vulnerability Checklist:**
- [ ] Buffer overflow
- [ ] Use-after-free
- [ ] Double-free
- [ ] Uninitialized memory
- [ ] Integer overflow
- [ ] Format string
- [ ] Type confusion

---

*AMD Debugging Doctrine - Adapted for Security Research*
*Memory First | Spec is Truth | No Undefined Behavior*
