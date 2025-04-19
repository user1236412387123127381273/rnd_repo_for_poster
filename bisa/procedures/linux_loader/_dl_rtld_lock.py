from __future__ import annotations
import bisa


class _dl_rtld_lock_recursive(bisa.SimProcedure):
    # pylint: disable=arguments-differ, unused-argument
    def run(self, lock):
        # For future reference:
        # ++((pthread_mutex_t *)(lock))->__data.__count;
        return


class _dl_rtld_unlock_recursive(bisa.SimProcedure):
    def run(self):
        return
