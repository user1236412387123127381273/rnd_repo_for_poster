from __future__ import annotations
import typing

from bisa.errors import SimMemoryError

if typing.TYPE_CHECKING:
    from bisa import Project


class IndirectJumpResolver:
    def __init__(self, project, timeless=False, base_state=None):
        self.project: Project = project
        self.timeless = timeless
        self.base_state = base_state

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        """
        Check if this resolution method may be able to resolve the indirect jump or not.

        :param int addr:        Basic block address of this indirect jump.
        :param int func_addr:   Address of the function that this indirect jump belongs to.
        :param block:           The basic block. The type is determined by the backend being used. It's pyvex.IRSB if
                                pyvex is used as the backend.
        :param str jumpkind:    The jumpkind.
        :return: True if it is possible for this resolution method to resolve the specific indirect jump, False
                 otherwise.
        :rtype:  bool
        """

        raise NotImplementedError

    def resolve(self, cfg, addr, func_addr, block, jumpkind, func_graph_complete: bool = True, **kwargs):
        """
        Resolve an indirect jump.

        :param cfg:             The CFG analysis object.
        :param int addr:        Basic block address of this indirect jump.
        :param int func_addr:   Address of the function that this indirect jump belongs to.
        :param block:           The basic block. The type is determined by the backend being used. It's pyvex.IRSB if
                                pyvex is used as the backend.
        :param str jumpkind:    The jumpkind.
        :param func_graph_complete: True if the function graph is complete at this point (except for nodes that this
                                indirect jump node dominates).
        :return:                A tuple of a boolean indicating whether the resolution is successful or not, and a list
                                of resolved targets (ints).
        :rtype:                 tuple
        """

        raise NotImplementedError

    def _is_target_valid(self, cfg, target):  # pylint:disable=no-self-use
        """
        Check if the resolved target is valid.

        :param cfg:         The CFG analysis object.
        :param int target:  The target to check.
        :return:            True if the target is valid. False otherwise.
        :rtype:             bool
        """

        if self.base_state is not None:
            try:
                if self.base_state.solver.is_true((self.base_state.memory.permissions(target) & 4) == 4):
                    return True
            except SimMemoryError:
                pass
            return False

        if cfg._addr_in_exec_memory_regions(target):
            # the jump target is executable
            return True

        # if true, the jump target is hooked
        return bool(self.project.is_hooked(target))
