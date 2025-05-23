from __future__ import annotations
import bisa


class error(bisa.SimProcedure):
    # pylint:disable=arguments-differ,missing-class-docstring

    NO_RET = None
    DYNAMIC_RET = True

    def run(self, status, errnum, fmt):  # pylint:disable=unused-argument
        fd = self.state.posix.get_fd(1)
        fprintf = bisa.SIM_PROCEDURES["libc"]["fprintf"]
        self.inline_call(fprintf, fd, fmt)  # FIXME: This will not properly replace format strings

        if status.concrete and self.state.solver.eval(status) != 0:
            self.exit(status)

    def dynamic_returns(self, blocks, **kwargs) -> bool:
        # Execute those blocks with a blank state, and then dump the arguments
        blank_state = bisa.SimState(
            project=self.project,
            mode="fastpath",
            cle_memory_backer=self.project.loader.memory,
            add_options={
                bisa.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                bisa.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            },
        )
        # Execute each block
        state = blank_state
        for idx, b in enumerate(blocks):
            successors = self.project.factory.default_engine.process(state, irsb=b, force_addr=b.addr)
            if successors.all_successors:
                state = successors.all_successors[0]
                # if it was a call before reaching the last block, pick the one with Ijk_FakeRet
                if (
                    idx < len(blocks) - 1
                    and b.jumpkind
                    and (b.jumpkind == "Ijk_Call" or b.jumpkind.startswith("Ijk_Sys"))
                ):
                    fakerets = [succ for succ in successors.all_successors if succ.history.jumpkind == "Ijk_FakeRet"]
                    if fakerets:
                        state = fakerets[0]
            else:
                break

        # take a look at the first argument (status)
        cc = bisa.default_cc(
            self.arch.name, platform=self.project.simos.name if self.project.simos is not None else None
        )(self.arch)
        ty = bisa.sim_type.parse_signature("void x(int, int, char*)").with_arch(self.arch)
        args = cc.get_args(state, ty)
        return bool(args[0].concrete and state.solver.eval(args[0]) == 0)
