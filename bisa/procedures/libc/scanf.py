from __future__ import annotations
import logging

from bisa.procedures.stubs.format_parser import ScanfFormatParser

l = logging.getLogger(name=__name__)


class scanf(ScanfFormatParser):
    # pylint:disable=arguments-differ,unused-argument

    def run(self, fmt):
        fmt_str = self._parse(fmt)

        # we're reading from stdin so the region is the file's content
        simfd = self.state.posix.get_fd(0)
        if simfd is None:
            return -1

        return fmt_str.interpret(self.va_arg, simfd=simfd)
