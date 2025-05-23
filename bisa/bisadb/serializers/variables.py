from __future__ import annotations
from typing import TYPE_CHECKING

from bisa.knowledge_plugins import VariableManager
from bisa.knowledge_plugins.variables.variable_manager import VariableManagerInternal
from bisa.bisadb.models import DbVariableCollection

if TYPE_CHECKING:
    from bisa.knowledge_base import KnowledgeBase
    from bisa.bisadb.models import DbKnowledgeBase


class VariableManagerSerializer:
    """
    Serialize/unserialize a variable manager and its variables.
    """

    @staticmethod
    def dump(session, db_kb: DbKnowledgeBase, var_manager: VariableManager):
        # Remove all existing variable collections
        session.query(DbVariableCollection).filter_by(kb=db_kb).delete()

        # Dump all variable manager internal instances
        for func_addr, internal in var_manager.function_managers.items():
            VariableManagerSerializer.dump_internal(session, db_kb, internal, func_addr, ident=None)
        # dump the global variable manager internal
        VariableManagerSerializer.dump_internal(session, db_kb, var_manager.global_manager, -1, ident=None)

    @staticmethod
    def dump_internal(
        session, db_kb: DbKnowledgeBase, internal_manager: VariableManagerInternal, func_addr: int, ident=None
    ):
        blob = internal_manager.serialize()

        db_varcoll = DbVariableCollection(kb=db_kb, ident=ident if ident else None, func_addr=func_addr, blob=blob)
        session.add(db_varcoll)

    @staticmethod
    def load(session, db_kb: DbKnowledgeBase, kb: KnowledgeBase, ident=None):
        variable_manager = VariableManager(kb)

        db_varcolls = session.query(DbVariableCollection).filter_by(kb=db_kb, ident=ident)
        for db_varcoll in db_varcolls:
            internal = VariableManagerSerializer.load_internal(db_varcoll, variable_manager)
            if internal.func_addr is None:
                variable_manager.global_manager = internal
            else:
                variable_manager.function_managers[internal.func_addr] = internal

        return variable_manager

    @staticmethod
    def load_internal(db_varcoll, variable_manager: VariableManager) -> VariableManagerInternal:
        return VariableManagerInternal.parse(
            db_varcoll.blob,
            variable_manager=variable_manager,
            func_addr=db_varcoll.func_addr if db_varcoll.func_addr != -1 else None,
        )
