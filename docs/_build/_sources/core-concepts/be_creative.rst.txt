A final word of advice
======================

Congratulations! If you've read this far through the book (editor's note: this
comment only really applies when we've actually finished writing all the TODOs
so far) then you've been introduced to all the fundamental components of bisa
necessary to get started with binary analysis.

Ultimately, bisa is just an emulator. It is a highly instrumentable and very
unique emulator with lots of considerations for environment, true, but at its
core, the work you do with bisa is about extracting knowledge about how a bunch
of bytecode behaves on a CPU. In designing bisa, we've tried to provide you with
the tools and abstractions on top of this emulator to make certain common tasks
more useful, but there's no problem you can't solve just by working with a
SimState and observing the affects of ``.step()``.

As you read further into this book, we'll describe more technical subjects and
how to tune bisa's behavior for complicated scenarios. This knowledge should
inform your use of bisa so you can take the quickest path to a solution to any
given problem, but ultimately, you will want to solve problems by exercising
creativity with the tools at your disposal. If you can take a problem and
wrangle it into a form where it has defined and tractable inputs and outputs,
you can absolutely use bisa to achieve your goals, given that these goals
involve analyzing binaries. None of the abstractions or instrumentations we
provide are the end-all of how to use bisa for a given task - bisa is designed
so it can be used in as integrated or as ad-hoc of a manner as you desire. If
you see a path from problem to solution, take it.

Of course, it's very difficult to become well-acquainted with such a huge piece
of technology as bisa. To this end you can absolutely lean on the community
(through the `bisa Discord server <http://discord.bisa.io>`_ is the best option)
to discuss bisa and solving problems with it.

Good luck!
