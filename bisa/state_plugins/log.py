from __future__ import annotations

import itertools
import logging

from bisa.errors import SimEventError
from bisa.sim_state import SimState
from .plugin import SimStatePlugin
from .sim_event import SimEvent
from .sim_action import SimAction, SimActionConstraint


l = logging.getLogger(name=__name__)


class SimStateLog(SimStatePlugin):
    def __init__(self, log=None):
        SimStatePlugin.__init__(self)

        # general events
        self.events = []

        if log is not None:
            self.events.extend(log.events)

    @property
    def actions(self):
        for e in self.events:
            if isinstance(e, SimAction):
                yield e

    def add_event(self, event_type, **kwargs):
        try:
            new_event = SimEvent(self.state, event_type, **kwargs)
            self.events.append(new_event)
        except TypeError as e:
            raise SimEventError("Exception encountered when logging event") from e

    def _add_event(self, event):
        self.events.append(event)

    def add_action(self, action):
        self.events.append(action)

    def extend_actions(self, new_actions):
        self.events.extend(new_actions)

    def events_of_type(self, event_type):
        return [e for e in self.events if e.type == event_type]

    def actions_of_type(self, action_type):
        return [action for action in self.actions if action.type == action_type]

    @property
    def fresh_constraints(self):
        # pylint: disable=no-member
        return [ev.constraint.ast for ev in self.events if isinstance(ev, SimActionConstraint)]

    @SimStatePlugin.memo
    def copy(self, memo):  # pylint: disable=unused-argument
        return SimStateLog(log=self)

    def _combine(self, others):
        all_events = [e.events for e in itertools.chain([self], others)]
        self.events = [SimEvent(self.state, "merge", event_lists=all_events)]
        return False

    def merge(self, others, merge_conditions, common_ancestor=None):  # pylint: disable=unused-argument
        return self._combine(others)

    def widen(self, others):
        return self._combine(others)

    def clear(self):
        s = self.state
        self.__init__()
        self.state = s
        # self.events = [ ]
        # self.temps.clear()
        # self.used_variables.clear()
        # self.input_variables.clear()


SimState.register_default("log", SimStateLog)
