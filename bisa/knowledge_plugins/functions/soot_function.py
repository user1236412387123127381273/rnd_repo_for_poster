# pylint:disable=super-init-not-called
from __future__ import annotations
import os
from collections import defaultdict

import networkx

from bisa.codenode import BlockNode
from .function import Function


class SootFunction(Function):
    """
    A representation of a function and various information about it.
    """

    def __init__(self, function_manager, addr, name=None, syscall=None):
        """
        Function constructor for Soot

        :param addr:            The address of the function.
        :param name:            (Optional) The name of the function.
        :param syscall:         (Optional) Whether this function is a syscall or not.
        """
        self.transition_graph = networkx.DiGraph()
        self._local_transition_graph = None
        # The Shimple CFG is already normalized.
        self.normalized = True

        # block nodes at whose ends the function returns
        self._ret_sites = set()
        # block nodes at whose ends the function jumps out to another function (jumps outside)
        self._jumpout_sites = set()
        # block nodes at whose ends the function calls out to another non-returning function
        self._callout_sites = set()
        # block nodes that ends the function by returning out to another function (returns outside). This is rare.
        self._retout_sites = set()
        # block nodes (basic block nodes) at whose ends the function terminates
        # in theory, if everything works fine, endpoints == ret_sites | jumpout_sites | callout_sites
        self._endpoints = defaultdict(set)
        self.previous_names = []

        self._call_sites = {}
        self.addr = addr
        self._function_manager = function_manager
        self.is_syscall = syscall

        self._project = project = self._function_manager._kb._project

        self.is_plt = False
        self.is_simprocedure = False

        if project.is_hooked(addr):
            self.is_simprocedure = True

        binary_name = None
        if self.is_simprocedure:
            hooker = project.hooked_by(addr)
            if hooker is not None:
                binary_name = hooker.library_name

        if binary_name is None and self.binary is not None:
            binary_name = os.path.basename(self.binary.binary)

        self._name = addr.__repr__()
        self.binary_name = binary_name

        # Stack offsets of those arguments passed in stack variables
        self._argument_stack_variables = []

        # These properties are set by VariableManager
        self.bp_on_stack = False
        self.retaddr_on_stack = False

        self.sp_delta = 0

        # Calling convention
        self.calling_convention = None

        # Function prototype
        self.prototype = None

        # Whether this function returns or not. `None` means it's not determined yet
        self._returning = None

        self.is_alignment = None

        # Determine returning status for SimProcedures and Syscalls
        hooker = None
        if self.is_simprocedure:
            hooker = project.hooked_by(addr)
        if hooker and hasattr(hooker, "NO_RET"):
            self.returning = not hooker.NO_RET

        # startpoint can always be None if this CFGNode is a syscall node
        self.startpoint = None

        self._addr_to_block_node = {}  # map addresses to nodes
        self._block_sizes = {}  # map addresses to block sizes
        self._block_cache = {}  # a cache of real, hard data Block objects
        self._local_blocks = {}  # a dict of all blocks inside the function
        self._local_block_addrs = set()  # a set of addresses of all blocks inside the function

        self.info = {}  # storing special information, like $gp values for MIPS32
        self.tags = ()  # store function tags. can be set manually by performing CodeTagging analysis.

    def normalize(self):
        # The Shimple CFG is already normalized.
        pass

    def _register_node(self, is_local: bool, node):
        if is_local and self._local_blocks.get(node.addr) == node:
            return self._local_blocks[node.addr]

        if node not in self.transition_graph:
            self.transition_graph.add_node(node)
        node._graph = self.transition_graph
        if node.addr not in self or self._block_sizes[node.addr] == 0:
            self._block_sizes[node.addr] = node.size
        if node.addr == self.addr.addr and (self.startpoint is None or not self.startpoint.is_hook):
            self.startpoint = node
        if is_local:
            self._local_blocks[node.addr] = node
            self._local_block_addrs.add(node.addr)
        # add BlockNodes to the addr_to_block_node cache if not already there
        if isinstance(node, BlockNode) and node.addr not in self._addr_to_block_node:
            self._addr_to_block_node[node.addr] = node
        return node
