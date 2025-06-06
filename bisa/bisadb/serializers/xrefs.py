# pylint:disable=unused-import
from __future__ import annotations
from bisa.bisadb.models import DbXRefs
from bisa.knowledge_plugins.xrefs import XRefManager


class XRefsSerializer:
    """
    Serialize/unserialize an XRefs object to/from a database session.
    """

    @staticmethod
    def dump(session, db_kb, xrefs):
        """

        :param session:
        :param DbKnowledgeBase db_kb:
        :param XRefManager xrefs:
        :return:
        """

        db_xrefs = db_kb.xrefs

        blob = xrefs.serialize()
        if db_xrefs is not None:
            # update the existing xrefs
            db_xrefs.blob = blob
        else:
            # create a new xrefs
            db_xrefs = DbXRefs(kb=db_kb, blob=blob)
            session.add(db_xrefs)

    @staticmethod
    def load(session, db_kb, kb, cfg_model=None):  # pylint:disable=unused-argument
        """

        :param session:
        :param DbKnowledgeBase db_kb:
        :param KnowledgeBase kb:
        :param CFGModel cfg_model:
        :return:
        """

        db_xrefs = db_kb.xrefs
        if db_xrefs is None:
            return None

        return XRefManager.parse(db_xrefs.blob, cfg_model=cfg_model, kb=kb)
