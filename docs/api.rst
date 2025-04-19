API Reference
=============

.. automodule:: bisa

Project
-------

.. automodule:: bisa.project
.. automodule:: bisa.factory
.. automodule:: bisa.block

Plugin Ecosystem
----------------

.. automodule:: bisa.misc.plugins

Program State
-------------
.. automodule:: bisa.sim_state
.. automodule:: bisa.sim_options
.. automodule:: bisa.sim_state_options
.. automodule:: bisa.state_plugins
.. automodule:: bisa.state_plugins.plugin
.. automodule:: bisa.state_plugins.inspect
.. automodule:: bisa.state_plugins.libc
.. automodule:: bisa.state_plugins.posix
.. automodule:: bisa.state_plugins.filesystem
.. automodule:: bisa.state_plugins.solver
.. automodule:: bisa.state_plugins.log
.. automodule:: bisa.state_plugins.callstack
.. automodule:: bisa.state_plugins.light_registers
.. automodule:: bisa.state_plugins.history
.. automodule:: bisa.state_plugins.gdb
.. automodule:: bisa.state_plugins.cgc
.. automodule:: bisa.state_plugins.trace_additions
.. automodule:: bisa.state_plugins.globals
.. automodule:: bisa.state_plugins.uc_manager
.. automodule:: bisa.state_plugins.scratch
.. automodule:: bisa.state_plugins.preconstrainer
.. automodule:: bisa.state_plugins.unicorn_engine
.. automodule:: bisa.state_plugins.loop_data
.. automodule:: bisa.state_plugins.concrete
.. automodule:: bisa.state_plugins.javavm_classloader
.. automodule:: bisa.state_plugins.jni_references
.. automodule:: bisa.state_plugins.heap
.. automodule:: bisa.state_plugins.heap.heap_base
.. automodule:: bisa.state_plugins.heap.heap_brk
.. automodule:: bisa.state_plugins.heap.heap_freelist
.. automodule:: bisa.state_plugins.heap.heap_libc
.. automodule:: bisa.state_plugins.heap.heap_ptmalloc
.. automodule:: bisa.state_plugins.heap.utils
.. automodule:: bisa.state_plugins.symbolizer
.. automodule:: bisa.state_plugins.debug_variables

Storage
-------

.. automodule:: bisa.storage
.. automodule:: bisa.state_plugins.view
.. automodule:: bisa.storage.file
.. automodule:: bisa.storage.memory_object
.. automodule:: bisa.storage.pcap
.. automodule:: bisa.concretization_strategies

Memory Mixins
-------------

.. automodule:: bisa.storage.memory_mixins
.. automodule:: bisa.storage.memory_mixins.name_resolution_mixin
.. automodule:: bisa.storage.memory_mixins.smart_find_mixin
.. automodule:: bisa.storage.memory_mixins.default_filler_mixin
.. automodule:: bisa.storage.memory_mixins.bvv_conversion_mixin
.. automodule:: bisa.storage.memory_mixins.hex_dumper_mixin
.. automodule:: bisa.storage.memory_mixins.underconstrained_mixin
.. automodule:: bisa.storage.memory_mixins.simple_interface_mixin
.. automodule:: bisa.storage.memory_mixins.actions_mixin
.. automodule:: bisa.storage.memory_mixins.symbolic_merger_mixin
.. automodule:: bisa.storage.memory_mixins.size_resolution_mixin
.. automodule:: bisa.storage.memory_mixins.dirty_addrs_mixin
.. automodule:: bisa.storage.memory_mixins.address_concretization_mixin
.. automodule:: bisa.storage.memory_mixins.clouseau_mixin
.. automodule:: bisa.storage.memory_mixins.conditional_store_mixin
.. automodule:: bisa.storage.memory_mixins.label_merger_mixin
.. automodule:: bisa.storage.memory_mixins.simplification_mixin
.. automodule:: bisa.storage.memory_mixins.unwrapper_mixin
.. automodule:: bisa.storage.memory_mixins.convenient_mappings_mixin
.. automodule:: bisa.storage.memory_mixins.paged_memory.pages.mv_list_page
.. automodule:: bisa.storage.memory_mixins.paged_memory.pages.multi_values
.. automodule:: bisa.storage.memory_mixins.top_merger_mixin
.. automodule:: bisa.storage.memory_mixins.multi_value_merger_mixin

.. automodule:: bisa.storage.memory_mixins.paged_memory
.. automodule:: bisa.storage.memory_mixins.paged_memory.paged_memory_mixin
.. automodule:: bisa.storage.memory_mixins.paged_memory.page_backer_mixins
.. automodule:: bisa.storage.memory_mixins.paged_memory.stack_allocation_mixin
.. automodule:: bisa.storage.memory_mixins.paged_memory.privileged_mixin
.. automodule:: bisa.storage.memory_mixins.paged_memory.pages
.. automodule:: bisa.storage.memory_mixins.paged_memory.pages.refcount_mixin
.. automodule:: bisa.storage.memory_mixins.paged_memory.pages.permissions_mixin
.. automodule:: bisa.storage.memory_mixins.paged_memory.pages.history_tracking_mixin
.. automodule:: bisa.storage.memory_mixins.paged_memory.pages.ispo_mixin
.. automodule:: bisa.storage.memory_mixins.paged_memory.pages.cooperation
.. automodule:: bisa.storage.memory_mixins.paged_memory.pages.list_page
.. automodule:: bisa.storage.memory_mixins.paged_memory.pages.ultra_page

.. automodule:: bisa.storage.memory_mixins.regioned_memory
.. automodule:: bisa.storage.memory_mixins.regioned_memory.regioned_memory_mixin
.. automodule:: bisa.storage.memory_mixins.regioned_memory.region_data
.. automodule:: bisa.storage.memory_mixins.regioned_memory.region_category_mixin
.. automodule:: bisa.storage.memory_mixins.regioned_memory.static_find_mixin
.. automodule:: bisa.storage.memory_mixins.regioned_memory.abstract_address_descriptor
.. automodule:: bisa.storage.memory_mixins.regioned_memory.region_meta_mixin
.. automodule:: bisa.storage.memory_mixins.regioned_memory.abstract_merger_mixin
.. automodule:: bisa.storage.memory_mixins.regioned_memory.regioned_address_concretization_mixin

.. automodule:: bisa.storage.memory_mixins.slotted_memory

.. automodule:: bisa.storage.memory_mixins.keyvalue_memory
.. automodule:: bisa.storage.memory_mixins.keyvalue_memory.keyvalue_memory_mixin

.. automodule:: bisa.storage.memory_mixins.javavm_memory
.. automodule:: bisa.storage.memory_mixins.javavm_memory.javavm_memory_mixin

Concretization Strategies
-------------------------

.. automodule:: bisa.concretization_strategies.single
.. automodule:: bisa.concretization_strategies.eval
.. automodule:: bisa.concretization_strategies.norepeats
.. automodule:: bisa.concretization_strategies.solutions
.. automodule:: bisa.concretization_strategies.nonzero_range
.. automodule:: bisa.concretization_strategies.range
.. automodule:: bisa.concretization_strategies.max
.. automodule:: bisa.concretization_strategies.norepeats_range
.. automodule:: bisa.concretization_strategies.nonzero
.. automodule:: bisa.concretization_strategies.any
.. automodule:: bisa.concretization_strategies.controlled_data
.. automodule:: bisa.concretization_strategies.unlimited_range


Simulation Manager
------------------

.. automodule:: bisa.sim_manager
.. automodule:: bisa.state_hierarchy

Exploration Techniques
----------------------

.. automodule:: bisa.exploration_techniques
.. automodule:: bisa.exploration_techniques.timeout
.. automodule:: bisa.exploration_techniques.dfs
.. automodule:: bisa.exploration_techniques.explorer
.. automodule:: bisa.exploration_techniques.lengthlimiter
.. automodule:: bisa.exploration_techniques.manual_mergepoint
.. automodule:: bisa.exploration_techniques.spiller
.. automodule:: bisa.exploration_techniques.spiller_db
.. automodule:: bisa.exploration_techniques.threading
.. automodule:: bisa.exploration_techniques.veritesting
.. automodule:: bisa.exploration_techniques.tracer
.. automodule:: bisa.exploration_techniques.driller_core
.. automodule:: bisa.exploration_techniques.slicecutor
.. automodule:: bisa.exploration_techniques.director
.. automodule:: bisa.exploration_techniques.oppologist
.. automodule:: bisa.exploration_techniques.loop_seer
.. automodule:: bisa.exploration_techniques.local_loop_seer
.. automodule:: bisa.exploration_techniques.stochastic
.. automodule:: bisa.exploration_techniques.unique
.. automodule:: bisa.exploration_techniques.tech_builder
.. automodule:: bisa.exploration_techniques.common
.. automodule:: bisa.exploration_techniques.symbion
.. automodule:: bisa.exploration_techniques.memory_watcher
.. automodule:: bisa.exploration_techniques.bucketizer
.. automodule:: bisa.exploration_techniques.suggestions

Simulation Engines
------------------

.. automodule:: bisa.engines
.. automodule:: bisa.engines.engine
.. automodule:: bisa.engines.successors
.. automodule:: bisa.engines.procedure
.. automodule:: bisa.engines.hook
.. automodule:: bisa.engines.syscall
.. automodule:: bisa.engines.failure
.. automodule:: bisa.engines.vex
.. automodule:: bisa.engines.soot
.. automodule:: bisa.engines.soot.engine
.. automodule:: bisa.engines.unicorn
.. automodule:: bisa.engines.concrete
.. automodule:: bisa.engines.pcode
.. automodule:: bisa.engines.pcode.engine
.. automodule:: bisa.engines.pcode.lifter
.. automodule:: bisa.engines.pcode.emulate
.. automodule:: bisa.engines.pcode.behavior
.. automodule:: bisa.engines.pcode.cc

Simulation Logging
------------------
.. automodule:: bisa.state_plugins.sim_action
.. automodule:: bisa.state_plugins.sim_action_object
.. automodule:: bisa.state_plugins.sim_event

Procedures
----------
.. automodule:: bisa.sim_procedure
.. automodule:: bisa.procedures
.. automodule:: bisa.procedures.stubs.format_parser
.. automodule:: bisa.procedures.definitions

Calling Conventions and Types
-----------------------------
.. automodule:: bisa.calling_conventions
.. automodule:: bisa.sim_variable
.. automodule:: bisa.sim_type
.. automodule:: bisa.callable

Knowledge Base
--------------

.. automodule:: bisa.knowledge_base
.. automodule:: bisa.knowledge_base.knowledge_base
.. automodule:: bisa.knowledge_plugins
.. automodule:: bisa.knowledge_plugins.patches
.. automodule:: bisa.knowledge_plugins.plugin
.. automodule:: bisa.knowledge_plugins.callsite_prototypes
.. automodule:: bisa.knowledge_plugins.cfg
.. automodule:: bisa.knowledge_plugins.cfg.cfg_model
.. automodule:: bisa.knowledge_plugins.cfg.memory_data
.. automodule:: bisa.knowledge_plugins.cfg.cfg_manager
.. automodule:: bisa.knowledge_plugins.cfg.cfg_node
.. automodule:: bisa.knowledge_plugins.cfg.indirect_jump
.. automodule:: bisa.knowledge_plugins.gotos
.. automodule:: bisa.knowledge_plugins.types
.. automodule:: bisa.knowledge_plugins.propagations
.. automodule:: bisa.knowledge_plugins.comments
.. automodule:: bisa.knowledge_plugins.data
.. automodule:: bisa.knowledge_plugins.indirect_jumps
.. automodule:: bisa.knowledge_plugins.labels
.. automodule:: bisa.knowledge_plugins.functions
.. automodule:: bisa.knowledge_plugins.functions.function_manager
    :members: FunctionManager
.. automodule:: bisa.knowledge_plugins.functions.function
.. automodule:: bisa.knowledge_plugins.functions.function_parser
.. automodule:: bisa.knowledge_plugins.functions.soot_function
.. automodule:: bisa.knowledge_plugins.variables
.. automodule:: bisa.knowledge_plugins.variables.variable_access
.. automodule:: bisa.knowledge_plugins.variables.variable_manager
.. automodule:: bisa.knowledge_plugins.debug_variables
.. automodule:: bisa.knowledge_plugins.structured_code
.. automodule:: bisa.knowledge_plugins.structured_code.manager
.. automodule:: bisa.knowledge_plugins.key_definitions
.. automodule:: bisa.knowledge_plugins.key_definitions.atoms
.. automodule:: bisa.knowledge_plugins.key_definitions.constants
.. automodule:: bisa.knowledge_plugins.key_definitions.definition
.. automodule:: bisa.knowledge_plugins.key_definitions.environment
.. automodule:: bisa.knowledge_plugins.key_definitions.heap_address
.. automodule:: bisa.knowledge_plugins.key_definitions.key_definition_manager
.. automodule:: bisa.knowledge_plugins.key_definitions.live_definitions
.. automodule:: bisa.knowledge_plugins.key_definitions.rd_model
.. automodule:: bisa.knowledge_plugins.key_definitions.tag
.. automodule:: bisa.knowledge_plugins.key_definitions.undefined
.. automodule:: bisa.knowledge_plugins.key_definitions.unknown_size
.. automodule:: bisa.knowledge_plugins.key_definitions.uses
.. automodule:: bisa.knowledge_plugins.sync
.. automodule:: bisa.knowledge_plugins.sync.sync_controller
.. automodule:: bisa.knowledge_plugins.xrefs
.. automodule:: bisa.knowledge_plugins.xrefs.xref
.. automodule:: bisa.knowledge_plugins.xrefs.xref_types
.. automodule:: bisa.knowledge_plugins.xrefs.xref_manager
.. automodule:: bisa.code_location
.. automodule:: bisa.keyed_region


Serialization
-------------

.. automodule:: bisa.serializable
.. automodule:: bisa.protos
.. automodule:: bisa.vaults


Analysis
--------

.. automodule:: bisa.analyses
.. automodule:: bisa.analyses.analysis
.. automodule:: bisa.analyses.forward_analysis
.. automodule:: bisa.analyses.forward_analysis.forward_analysis
.. automodule:: bisa.analyses.forward_analysis.job_info
.. automodule:: bisa.analyses.forward_analysis.visitors
.. automodule:: bisa.analyses.forward_analysis.visitors.call_graph
.. automodule:: bisa.analyses.forward_analysis.visitors.function_graph
.. automodule:: bisa.analyses.forward_analysis.visitors.graph
.. automodule:: bisa.analyses.forward_analysis.visitors.loop
.. automodule:: bisa.analyses.forward_analysis.visitors.single_node_graph
.. automodule:: bisa.analyses.backward_slice
.. automodule:: bisa.analyses.bindiff
.. automodule:: bisa.analyses.boyscout
.. automodule:: bisa.analyses.calling_convention
.. automodule:: bisa.analyses.complete_calling_conventions
.. automodule:: bisa.analyses.soot_class_hierarchy
.. automodule:: bisa.analyses.cfg
.. automodule:: bisa.analyses.cfg.cfb
.. automodule:: bisa.analyses.cfg.cfg
.. automodule:: bisa.analyses.cfg.cfg_emulated
.. automodule:: bisa.analyses.cfg.cfg_base
.. automodule:: bisa.analyses.cfg.cfg_fast
.. automodule:: bisa.analyses.cfg.cfg_arch_options
.. automodule:: bisa.analyses.cfg.cfg_job_base
.. automodule:: bisa.analyses.cfg.indirect_jump_resolvers.amd64_elf_got
.. automodule:: bisa.analyses.cfg.indirect_jump_resolvers.arm_elf_fast
.. automodule:: bisa.analyses.cfg.indirect_jump_resolvers.x86_pe_iat
.. automodule:: bisa.analyses.cfg.indirect_jump_resolvers.mips_elf_fast
.. automodule:: bisa.analyses.cfg.indirect_jump_resolvers.x86_elf_pic_plt
.. automodule:: bisa.analyses.cfg.indirect_jump_resolvers.default_resolvers
.. automodule:: bisa.analyses.cfg.indirect_jump_resolvers.jumptable
.. automodule:: bisa.analyses.cfg.indirect_jump_resolvers.const_resolver
.. automodule:: bisa.analyses.cfg.indirect_jump_resolvers.resolver
.. automodule:: bisa.analyses.cfg.indirect_jump_resolvers
.. automodule:: bisa.analyses.cfg.cfg_fast_soot
.. automodule:: bisa.analyses.cfg.segment_list
.. automodule:: bisa.analyses.cdg
.. automodule:: bisa.analyses.datagraph_meta
.. automodule:: bisa.analyses.code_tagging
.. automodule:: bisa.bisadb
.. automodule:: bisa.bisadb.db
.. automodule:: bisa.bisadb.models
.. automodule:: bisa.bisadb.serializers
.. automodule:: bisa.bisadb.serializers.cfg_model
.. automodule:: bisa.bisadb.serializers.comments
.. automodule:: bisa.bisadb.serializers.funcs
.. automodule:: bisa.bisadb.serializers.kb
.. automodule:: bisa.bisadb.serializers.labels
.. automodule:: bisa.bisadb.serializers.loader
.. automodule:: bisa.bisadb.serializers.xrefs
.. automodule:: bisa.bisadb.serializers.variables
.. automodule:: bisa.bisadb.serializers.structured_code
.. automodule:: bisa.analyses.decompiler.structuring.recursive_structurer
.. automodule:: bisa.analyses.decompiler.structuring
.. automodule:: bisa.analyses.decompiler.structuring.dream
.. automodule:: bisa.analyses.decompiler.structuring.structurer_nodes
.. automodule:: bisa.analyses.decompiler.structuring.structurer_base
.. automodule:: bisa.analyses.decompiler.structuring.phoenix
.. automodule:: bisa.analyses.decompiler
.. automodule:: bisa.analyses.decompiler.ail_simplifier
.. automodule:: bisa.analyses.decompiler.ailgraph_walker
.. automodule:: bisa.analyses.decompiler.block_simplifier
.. automodule:: bisa.analyses.decompiler.callsite_maker
.. automodule:: bisa.analyses.decompiler.ccall_rewriters
.. automodule:: bisa.analyses.decompiler.ccall_rewriters.rewriter_base
.. automodule:: bisa.analyses.decompiler.ccall_rewriters.amd64_ccalls
.. automodule:: bisa.analyses.decompiler.clinic
.. automodule:: bisa.analyses.decompiler.condition_processor
.. automodule:: bisa.analyses.decompiler.decompilation_options
.. automodule:: bisa.analyses.decompiler.decompilation_cache
.. automodule:: bisa.analyses.decompiler.decompiler
.. automodule:: bisa.analyses.decompiler.empty_node_remover
.. automodule:: bisa.analyses.decompiler.expression_narrower
.. automodule:: bisa.analyses.decompiler.graph_region
.. automodule:: bisa.analyses.decompiler.jump_target_collector
.. automodule:: bisa.analyses.decompiler.jumptable_entry_condition_rewriter
.. automodule:: bisa.analyses.decompiler.optimization_passes
.. automodule:: bisa.analyses.decompiler.optimization_passes.const_derefs
.. automodule:: bisa.analyses.decompiler.optimization_passes.eager_returns
.. automodule:: bisa.analyses.decompiler.optimization_passes.optimization_pass
.. automodule:: bisa.analyses.decompiler.optimization_passes.stack_canary_simplifier
.. automodule:: bisa.analyses.decompiler.optimization_passes.base_ptr_save_simplifier
.. automodule:: bisa.analyses.decompiler.optimization_passes.div_simplifier
.. automodule:: bisa.analyses.decompiler.optimization_passes.ite_expr_converter
.. automodule:: bisa.analyses.decompiler.optimization_passes.lowered_switch_simplifier
.. automodule:: bisa.analyses.decompiler.optimization_passes.multi_simplifier
.. automodule:: bisa.analyses.decompiler.optimization_passes.mod_simplifier
.. automodule:: bisa.analyses.decompiler.optimization_passes.engine_base
.. automodule:: bisa.analyses.decompiler.optimization_passes.expr_op_swapper
.. automodule:: bisa.analyses.decompiler.optimization_passes.register_save_area_simplifier
.. automodule:: bisa.analyses.decompiler.optimization_passes.ret_addr_save_simplifier
.. automodule:: bisa.analyses.decompiler.optimization_passes.x86_gcc_getpc_simplifier
.. automodule:: bisa.analyses.decompiler.peephole_optimizations
.. automodule:: bisa.analyses.decompiler.peephole_optimizations.base
.. automodule:: bisa.analyses.decompiler.region_identifier
.. automodule:: bisa.analyses.decompiler.region_simplifiers
.. automodule:: bisa.analyses.decompiler.region_simplifiers.cascading_cond_transformer
.. automodule:: bisa.analyses.decompiler.region_simplifiers.cascading_ifs
.. automodule:: bisa.analyses.decompiler.region_simplifiers.expr_folding
.. automodule:: bisa.analyses.decompiler.region_simplifiers.goto
.. automodule:: bisa.analyses.decompiler.region_simplifiers.if_
.. automodule:: bisa.analyses.decompiler.region_simplifiers.ifelse
.. automodule:: bisa.analyses.decompiler.region_simplifiers.loop
.. automodule:: bisa.analyses.decompiler.region_simplifiers.node_address_finder
.. automodule:: bisa.analyses.decompiler.region_simplifiers.region_simplifier
.. automodule:: bisa.analyses.decompiler.region_simplifiers.switch_cluster_simplifier
.. automodule:: bisa.analyses.decompiler.region_simplifiers.switch_expr_simplifier
.. automodule:: bisa.analyses.decompiler.region_walker
.. automodule:: bisa.analyses.decompiler.redundant_label_remover
.. automodule:: bisa.analyses.decompiler.sequence_walker
.. automodule:: bisa.analyses.decompiler.structured_codegen
.. automodule:: bisa.analyses.decompiler.structured_codegen.base
.. automodule:: bisa.analyses.decompiler.structured_codegen.c
.. automodule:: bisa.analyses.decompiler.structured_codegen.dwarf_import
.. automodule:: bisa.analyses.decompiler.structured_codegen.dummy
.. automodule:: bisa.analyses.decompiler.utils
.. automodule:: bisa.analyses.ddg
.. automodule:: bisa.analyses.flirt
.. automodule:: bisa.engines.light.data
.. automodule:: bisa.engines.light
.. automodule:: bisa.engines.light.engine
.. automodule:: bisa.analyses.propagator
.. automodule:: bisa.analyses.propagator.values
.. automodule:: bisa.analyses.propagator.vex_vars
.. automodule:: bisa.analyses.propagator.call_expr_finder
.. automodule:: bisa.analyses.propagator.engine_base
.. automodule:: bisa.analyses.propagator.engine_vex
.. automodule:: bisa.analyses.propagator.engine_ail
.. automodule:: bisa.analyses.propagator.outdated_definition_walker
.. automodule:: bisa.analyses.propagator.tmpvar_finder
.. automodule:: bisa.analyses.propagator.propagator
.. automodule:: bisa.analyses.propagator.prop_value
.. automodule:: bisa.analyses.propagator.top_checker_mixin
.. automodule:: bisa.analyses.reaching_definitions
.. automodule:: bisa.analyses.reaching_definitions.call_trace
.. automodule:: bisa.analyses.reaching_definitions.engine_vex
.. automodule:: bisa.analyses.reaching_definitions.reaching_definitions
.. automodule:: bisa.analyses.reaching_definitions.dep_graph
.. automodule:: bisa.analyses.reaching_definitions.heap_allocator
.. automodule:: bisa.analyses.reaching_definitions.function_handler
.. automodule:: bisa.analyses.reaching_definitions.rd_state
.. automodule:: bisa.analyses.reaching_definitions.subject
.. automodule:: bisa.analyses.reaching_definitions.engine_ail
.. automodule:: bisa.analyses.cfg_slice_to_sink
.. automodule:: bisa.analyses.cfg_slice_to_sink.cfg_slice_to_sink
.. automodule:: bisa.analyses.cfg_slice_to_sink.graph
.. automodule:: bisa.analyses.cfg_slice_to_sink.transitions
.. automodule:: bisa.analyses.stack_pointer_tracker
.. automodule:: bisa.analyses.variable_recovery.annotations
.. automodule:: bisa.analyses.variable_recovery.variable_recovery_base
.. automodule:: bisa.analyses.variable_recovery.variable_recovery_fast
.. automodule:: bisa.analyses.variable_recovery.variable_recovery
.. automodule:: bisa.analyses.variable_recovery.engine_ail
.. automodule:: bisa.analyses.variable_recovery.engine_vex
.. automodule:: bisa.analyses.variable_recovery.engine_base
.. automodule:: bisa.analyses.variable_recovery.irsb_scanner
.. automodule:: bisa.analyses.variable_recovery
.. automodule:: bisa.analyses.typehoon.lifter
.. automodule:: bisa.analyses.typehoon.simple_solver
.. automodule:: bisa.analyses.typehoon.translator
.. automodule:: bisa.analyses.typehoon.typevars
.. automodule:: bisa.analyses.typehoon.typehoon
.. automodule:: bisa.analyses.typehoon.typeconsts
.. automodule:: bisa.analyses.typehoon
.. automodule:: bisa.analyses.identifier.identify
.. automodule:: bisa.analyses.loopfinder
.. automodule:: bisa.analyses.loop_analysis
.. automodule:: bisa.analyses.veritesting
.. automodule:: bisa.analyses.vfg
.. automodule:: bisa.analyses.vsa_ddg
.. automodule:: bisa.analyses.vtable
.. automodule:: bisa.analyses.find_objects_static
.. automodule:: bisa.analyses.class_identifier
.. automodule:: bisa.analyses.disassembly
.. automodule:: bisa.analyses.disassembly_utils
.. automodule:: bisa.analyses.reassembler
.. automodule:: bisa.analyses.congruency_check
.. automodule:: bisa.analyses.static_hooker
.. automodule:: bisa.analyses.binary_optimizer
.. automodule:: bisa.analyses.callee_cleanup_finder
.. automodule:: bisa.analyses.dominance_frontier
.. automodule:: bisa.analyses.init_finder
.. automodule:: bisa.analyses.xrefs
.. automodule:: bisa.analyses.proximity_graph
.. automodule:: bisa.analyses.data_dep.data_dependency_analysis
.. automodule:: bisa.analyses.data_dep.sim_act_location
.. automodule:: bisa.analyses.data_dep.dep_nodes
.. automodule:: bisa.analyses.data_dep
.. automodule:: bisa.blade
.. automodule:: bisa.slicer
.. automodule:: bisa.annocfg
.. automodule:: bisa.codenode


SimOS
-----

.. automodule:: bisa.simos
.. automodule:: bisa.simos.simos
.. automodule:: bisa.simos.linux
.. automodule:: bisa.simos.cgc
.. automodule:: bisa.simos.userland
.. automodule:: bisa.simos.windows
.. automodule:: bisa.simos.javavm

Function Signature Matching
---------------------------

.. automodule:: bisa.flirt
.. automodule:: bisa.flirt.build_sig


Utils
-----
.. automodule:: bisa.utils
.. automodule:: bisa.utils.algo
.. automodule:: bisa.utils.constants
.. automodule:: bisa.utils.cowdict
.. automodule:: bisa.utils.dynamic_dictlist
.. automodule:: bisa.utils.enums_conv
.. automodule:: bisa.utils.env
.. automodule:: bisa.utils.graph
.. automodule:: bisa.utils.lazy_import
.. automodule:: bisa.utils.loader
.. automodule:: bisa.utils.library
.. automodule:: bisa.utils.timing
.. automodule:: bisa.utils.formatting
.. automodule:: bisa.utils.mp

Errors
------
.. automodule:: bisa.errors

Distributed analysis
--------------------
.. automodule:: bisa.distributed
.. automodule:: bisa.distributed.server
.. automodule:: bisa.distributed.worker
