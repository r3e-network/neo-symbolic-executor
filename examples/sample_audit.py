"""Sample audit script demonstrating programmatic usage."""
from pathlib import Path
from neo_sym.nef.parser import parse_nef, disassemble, NefFile
from neo_sym.nef.opcodes import OpCode
from neo_sym.engine.symbolic import SymbolicEngine
from neo_sym.detectors import ALL_DETECTORS
from neo_sym.report.generator import ReportGenerator


def demo_with_synthetic_contract():
    """Demonstrate analysis with a synthetic NeoVM script."""
    # Build a simple contract script:
    # INITSLOT 1 local, 1 arg -> LDARG0 -> STLOC0 -> LDLOC0 -> RET
    script = bytes([
        OpCode.INITSLOT, 0x01, 0x01,
        OpCode.LDARG0,
        OpCode.STLOC0,
        OpCode.LDLOC0,
        OpCode.PUSH1,
        OpCode.ADD,
        OpCode.RET,
    ])
    nef = NefFile(script=script, instructions=disassemble(script))
    engine = SymbolicEngine(nef)
    states = engine.run()
    print(f"Explored {len(states)} paths")

    findings = []
    for name, cls in ALL_DETECTORS.items():
        findings.extend(cls().detect(states))

    gen = ReportGenerator("SyntheticContract")
    print(gen.to_markdown(findings))


if __name__ == "__main__":
    demo_with_synthetic_contract()
