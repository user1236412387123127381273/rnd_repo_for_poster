from __future__ import annotations
import bisa


class ReturnUnconstrained(bisa.SimProcedure):
    ARGS_MISMATCH = True

    def run(self, *args, **kwargs):  # pylint:disable=arguments-differ
        # pylint:disable=attribute-defined-outside-init

        return_val = kwargs.pop("return_val", None)
        if return_val is None:
            # code duplicated to syscall_stub
            size = self.prototype.returnty.size
            if size is None:
                o = None
            else:
                o = self.state.solver.Unconstrained(
                    f"unconstrained_ret_{self.display_name}", size, key=("api", "?", self.display_name)
                )
        else:
            o = return_val

        return o
