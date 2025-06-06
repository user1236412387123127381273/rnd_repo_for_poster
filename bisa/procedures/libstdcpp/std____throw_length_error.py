from __future__ import annotations
import bisa


class std____throw_logic_error(bisa.SimProcedure):  # pylint:disable=redefined-builtin
    # pylint:disable=arguments-differ

    NO_RET = True
    ALT_NAMES = ("std::__throw_length_error(char const*)",)

    def run(self, error):  # pylint:disable=unused-argument
        # FIXME: we need the concept of C++ exceptions to implement this right
        self.exit(1)
