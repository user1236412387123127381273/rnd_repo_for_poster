# pylint:disable=missing-class-docstring
from __future__ import annotations


class BISAError(Exception):
    pass


class BISARuntimeError(RuntimeError):
    pass


class BISAValueError(BISAError, ValueError):
    pass


class BISALifterError(BISAError):
    pass


class BISAExitError(BISAError):
    pass


class BISAPathError(BISAError):
    pass


class BISAVaultError(BISAError):
    pass


class PathUnreachableError(BISAPathError):
    pass


class SimulationManagerError(BISAError):
    pass


class BISAInvalidArgumentError(BISAError):
    pass


class BISASurveyorError(BISAError):
    pass


class BISAAnalysisError(BISAError):
    pass


class BISABladeError(BISAError):
    pass


class BISABladeSimProcError(BISABladeError):
    pass


class BISAAnnotatedCFGError(BISAError):
    pass


class BISABackwardSlicingError(BISAError):
    pass


class BISACallableError(BISASurveyorError):
    pass


class BISACallableMultistateError(BISACallableError):
    pass


class BISASyscallError(BISAError):
    pass


class BISASimOSError(BISAError):
    pass


class BISAAssemblyError(BISAError):
    pass


class BISATypeError(BISAError, TypeError):
    pass


class BISAMissingTypeError(BISATypeError):
    pass


# Congruency check failure
class BISAIncongruencyError(BISAAnalysisError):
    pass


#
# ForwardAnalysis errors
#


class BISAForwardAnalysisError(BISAError):
    pass


class BISASkipJobNotice(BISAForwardAnalysisError):
    pass


class BISADelayJobNotice(BISAForwardAnalysisError):
    pass


class BISAJobMergingFailureNotice(BISAForwardAnalysisError):
    pass


class BISAJobWideningFailureNotice(BISAForwardAnalysisError):
    pass


#
# CFG errors
#


class BISACFGError(BISAError):
    pass


#
# VFG Errors and notices
#


class BISAVFGError(BISAError):
    pass


class BISAVFGRestartAnalysisNotice(BISAVFGError):
    pass


#
# Data graph errors
#


class BISADataGraphError(BISAAnalysisError):
    # TODO: deprecated
    pass


class BISADDGError(BISAAnalysisError):
    pass


#
# Loop analysis
#


class BISALoopAnalysisError(BISAAnalysisError):
    pass


#
# Exploration techniques
#


class BISAExplorationTechniqueError(BISAError):
    pass


class BISAExplorerError(BISAExplorationTechniqueError):
    pass


class BISADirectorError(BISAExplorationTechniqueError):
    pass


class BISATracerError(BISAExplorationTechniqueError):
    pass


#
# VariableRecovery errors
#


class BISAVariableRecoveryError(BISAAnalysisError):
    pass


#
# BISADB errors
#


class BISADBError(BISAError):
    pass


class BISACorruptDBError(BISADBError):
    pass


class BISAIncompatibleDBError(BISADBError):
    pass


#
# Tracer
#


class TracerEnvironmentError(BISAError):
    pass


#
# Simulation errors
#


class SimError(Exception):
    bbl_addr = None
    stmt_idx = None
    ins_addr = None
    executed_instruction_count = None
    guard = None

    def record_state(self, state):
        self.bbl_addr = state.scratch.bbl_addr
        self.stmt_idx = state.scratch.stmt_idx
        self.ins_addr = state.scratch.ins_addr
        self.executed_instruction_count = state.history.recent_instruction_count
        self.guard = state.scratch.guard
        return self


#
# State-related errors
#


class SimStateError(SimError):
    pass


class SimMergeError(SimStateError):
    pass


class SimMemoryError(SimStateError):
    pass


class SimMemoryMissingError(SimMemoryError):
    def __init__(self, missing_addr, missing_size, *args):
        super().__init__(missing_addr, missing_size, *args)
        self.missing_addr = missing_addr
        self.missing_size = missing_size


class SimAbstractMemoryError(SimMemoryError):
    pass


class SimRegionMapError(SimMemoryError):
    pass


class SimMemoryLimitError(SimMemoryError):
    pass


class SimMemoryAddressError(SimMemoryError):
    pass


class SimFastMemoryError(SimMemoryError):
    pass


class SimEventError(SimStateError):
    pass


class SimPosixError(SimStateError):
    pass


class SimFilesystemError(SimError):
    pass


class SimSymbolicFilesystemError(SimFilesystemError):
    pass


class SimFileError(SimMemoryError, SimFilesystemError):
    pass


class SimHeapError(SimStateError):
    pass


#
# Error class during VEX parsing
#


class SimUnsupportedError(SimError):
    pass


#
# Solver-related errors
#


class SimSolverError(SimError):
    pass


class SimSolverModeError(SimSolverError):
    pass


class SimSolverOptionError(SimSolverError):
    pass


class SimValueError(SimSolverError):
    pass


class SimUnsatError(SimValueError):
    pass


#
# SimIROp errors
#


class SimOperationError(SimError):
    pass


class UnsupportedIROpError(SimOperationError, SimUnsupportedError):
    pass


#
# SimIRExpr errors
#


class SimExpressionError(SimError):
    pass


class UnsupportedIRExprError(SimExpressionError, SimUnsupportedError):
    pass


class SimCCallError(SimExpressionError):
    pass


class UnsupportedCCallError(SimCCallError, SimUnsupportedError):
    pass


class SimUninitializedAccessError(SimExpressionError):
    def __init__(self, expr_type, expr):
        SimExpressionError.__init__(self)
        self.expr_type = expr_type
        self.expr = expr

    def __repr__(self):
        return f"SimUninitializedAccessError (expr {self.expr} is used as {self.expr_type})"

    def __reduce__(self):
        return (SimUninitializedAccessError, (self.expr_type, self.expr))


#
# SimIRStmt errors
#


class SimStatementError(SimError):
    pass


class UnsupportedIRStmtError(SimStatementError, SimUnsupportedError):
    pass


class UnsupportedDirtyError(UnsupportedIRStmtError, SimUnsupportedError):
    pass


class SimMissingTempError(SimValueError, IndexError):
    pass


#
# Engine-related errors
#


class SimEngineError(SimError):
    pass


class SimIRSBError(SimEngineError):
    pass


class SimTranslationError(SimEngineError):
    pass


class SimProcedureError(SimEngineError):
    pass


class SimProcedureArgumentError(SimProcedureError):
    pass


class SimShadowStackError(SimProcedureError):
    pass


class SimFastPathError(SimEngineError):
    pass


class SimIRSBNoDecodeError(SimIRSBError):
    pass


class BISAUnsupportedSyscallError(BISASyscallError, SimProcedureError, SimUnsupportedError):
    pass


UnsupportedSyscallError = BISAUnsupportedSyscallError


class SimReliftException(SimEngineError):
    def __init__(self, state):
        super().__init__()
        self.state = state


#
# SimSlicer errors
#


class SimSlicerError(SimError):
    pass


#
# SimAction errors
#


class SimActionError(SimError):
    pass


#
# SimCC errors
#


class SimCCError(SimError):
    pass


#
# UCManager errors
#


class SimUCManagerError(SimError):
    pass


class SimUCManagerAllocationError(SimUCManagerError):
    pass


#
# SimUnicorn errors
#


class SimUnicornUnsupport(SimError):
    pass


class SimUnicornError(SimError):
    pass


class SimUnicornSymbolic(SimError):
    pass


#
# Call-stack Errors
#


class SimEmptyCallStackError(SimError):
    pass


#
# SimStateOptions Errors
#


class SimStateOptionsError(SimError):
    pass


#
# Errors that may be handled by exception handling
#


class SimException(SimError):
    pass


class SimSegfaultException(SimException, SimMemoryError):
    def __init__(self, addr, reason, original_addr=None):
        self.addr = addr
        self.reason = reason
        self.original_addr = original_addr
        super(SimSegfaultError, self).__init__(f"{addr:#x} ({reason})")

    def __repr__(self):
        return "SimSegfaultException({:#x} ({}{})".format(
            self.addr,
            self.reason,
            (f", original {self.original_addr.__repr__(max_depth=3)}") if self.original_addr is not None else "",
        )

    def __reduce__(self):
        return (SimSegfaultException, (self.addr, self.reason, self.original_addr))


SimSegfaultError = SimSegfaultException


class SimZeroDivisionException(SimException, SimOperationError):
    pass


class BISANoPluginError(BISAError):
    pass


#
# Concrete Targets Execution errors
#


class SimConcreteMemoryError(BISAError):
    pass


class SimConcreteRegisterError(BISAError):
    pass


class SimConcreteBreakpointError(BISAError):
    pass


#
# Decompiler errors
#


class BISADecompilationError(BISAError):
    pass


class UnsupportedNodeTypeError(BISAError, NotImplementedError):
    pass
