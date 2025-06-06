# Performance tests on concrete code execution without invoking Unicorn engine
# uses a stripped-down SimEngine to only test the essential pieces
# TODO also use a stripped-down memory
from __future__ import annotations

import os
import time

import bisa
import claripy

# attempt to turn off claripy debug mode
if hasattr(claripy, "set_debug"):
    claripy.set_debug(False)

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../binaries")


class SkinnyEngine(
    bisa.engines.SimEngineFailure, bisa.engines.SimEngineSyscall, bisa.engines.HooksMixin, bisa.engines.HeavyVEXMixin
):
    pass


arch = "x86_64"
b = bisa.Project(os.path.join(test_location, "tests", arch, "perf_tight_loops"), auto_load_libs=False)
state = b.factory.full_init_state(
    plugins={"registers": bisa.state_plugins.SimLightRegisters()}, remove_options={bisa.sim_options.COPY_STATES}
)
engine = SkinnyEngine(b)


def main():
    simgr = b.factory.simgr(state)
    simgr.explore(engine=engine)


if __name__ == "__main__":
    tstart = time.time()
    main()
    tend = time.time()
    print("Elapsed: %f sec" % (tend - tstart))
