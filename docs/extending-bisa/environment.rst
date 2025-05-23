Extending the Environment Model
===============================

One of the biggest issues you may encounter while using bisa to analyze programs
is an incomplete model of the environment, or the APIs, surrounding your
program. This usually takes the form of syscalls or dynamic library calls, or in
rare cases, loader artifacts. bisa provides a convenient interface to do most of
these things!

Everything discussed here involves writing SimProcedures, so :ref:`make sure you
know how to do that! <Hooks and SimProcedures>`.

Note that this page should be treated as a narrative document, not a reference
document, so you should read it at least once start to end.

Setup
-----

You *probably* want to have a development install of bisa, i.e. set up with the
script in the `bisa-dev repository <https://github.com/bisa/bisa-dev>`_. It is
remarkably easy to add new API models by just implementing them in certain
folders of the bisa repository. This is also desirable because any work you do
in this field will almost always be useful to other people, and this makes it
extremely easy to submit a pull request.

However, if you want to do your development out-of-tree, you want to work
against a production version of bisa, or you want to make customized versions of
already-implemented API functions, there are ways to incorporate your extensions
programmatically. Both these techniques, in-tree and out-of-tree, will be
documented at each step.

Dynamic library functions - import dependencies
-----------------------------------------------

This is the easiest case, and the case that SimProcedures were originally
designed for.

First, you need to write a SimProcedure representing the function.
Then you need to let bisa know about it.

Case 1, in-tree development: SimLibraries and catalogues
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

bisa has a magical folder in its repository, `bisa/procedures
<https://github.com/bisa/bisa/tree/master/bisa/procedures>`_. Within it are all
the SimProcedure implementations that come bundled with bisa as well as
information about what libraries implement what functions.

Each folder in the ``procedures`` directory corresponds to some sort of
*standard*, or a body that specifies the interface part of an API and its
semantics. We call each folder a *catalog* of procedures. For example, we have
``libc`` which contains the functions defined by the C standard library, and a
separate folder ``posix`` which contains the functions defined by the posix
standard. There is some magic which automatically scrapes these folders in the
``procedures`` directory and organizes them into the ``bisa.SIM_PROCEDURES``
dict. For example, ``bisa/procedures/libc/printf.py`` contains both ``class
printf`` and ``class __printf_chk``, so there exists both
``bisa.SIM_PROCEDURES['libc']['printf']`` and
``bisa.SIM_PROCEDURES['libc']['__printf_chk']``.

The purpose of this categorization is to enable easy sharing of procedures among
different libraries. For example. libc.so.6 contains all the C standard library
functions, but so does msvcrt.dll! These relationships are represented with
objects called ``SimLibraries`` which represent an actual shared library file,
its functions, and their metadata. Take a look at the API reference for
:py:class:`~bisa.procedures.definitions.SimLibrary` along with `the code for
setting up glibc
<https://github.com/bisa/bisa/blob/master/bisa/procedures/definitions/glibc.py>`_
to learn how to use it.

SimLibraries are defined in a special folder in the procedures directory,
``procedures/definitions``. Files in here should contain an *instance*, not a
subclass, of ``SimLibrary``. The same magic that scrapes up SimProcedures will
also scrape up SimLibraries and put them in ``bisa.SIM_LIBRARIES``, keyed on
each of their common names. For example,
``bisa/procedures/definitions/linux_loader.py`` contains ``lib = SimLibrary();
lib.set_library_names('ld.so', 'ld-linux.so', 'ld.so.2', 'ld-linux.so.2',
'ld-linux-x86_64.so.2')``, so you can access it via
``bisa.SIM_LIBRARIES['ld.so'][0]`` or ``bisa.SIM_LIBRARIES['ld-linux.so'][0]``
or any of the other names.

At load time, all the dynamic library dependencies are looked up in
``SIM_LIBRARIES`` and their procedures (or stubs!) are hooked into the project's
address space to summarize any functions it can. The code for this process is
found `here <https://github.com/bisa/bisa/blob/master/bisa/project.py#L244>`_.

**SO**, the bottom line is that you can just write your own SimProcedure and
SimLibrary definitions, drop them into the directory structure, and they'll
automatically be applied. If you're adding a procedure to an existing library,
you can just drop it into the appropriate catalog and it'll be picked up by all
the libraries using that catalog, since most libraries construct their list of
function implementation by batch-adding entire catalogs.

Case 2, out-of-tree development, tight integration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you'd like to implement your procedures outside the bisa repository, you can
do that. You effectively do this by just manually adding your procedures to the
appropriate SimLibrary. Just call ``bisa.SIM_LIBRARIES[libname][0].add(name,
proc_cls)`` to do the registration.

Note that this will only work if you do this before the project is loaded with
``bisa.Project``. Note also that adding the procedure to
``bisa.SIM_PROCEDURES``, i.e. adding it directly to a catalog, will *not* work,
since these catalogs are used to construct the SimLibraries only at import and
are used by value, not by reference.

Case 3, out-of-tree development, loose integration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Finally, if you don't want to mess with SimLibraries at all, you can do things
purely on the project level with :py:meth:`~bisa.project.Project.hook_symbol`.

Syscalls
--------

Unlike dynamic library methods, syscall procedures aren't incorporated into the
project via hooks. Instead, whenever a syscall instruction is encountered, the
basic block should end with a jumpkind of ``Ijk_Sys``. This will cause the next
step to be handled by the SimOS associated with the project, which will extract
the syscall number from the state and query a specialized SimLibrary with that.

This deserves some explanation.

There is a subclass of SimLibrary called SimSyscallLibrary which is used for
collecting all the functions that are part of an operating system's syscall
interface. SimSyscallLibrary uses the same system for managing implementations
and metadata as SimLibrary, but adds on top of it a system for managing syscall
numbers for multiple ABIs (application binary interfaces, like an API but lower
level). The best example for an implementation of a SimSyscallLibrary is the
`linux syscalls
<https://github.com/bisa/bisa/blob/master/bisa/procedures/definitions/linux_kernel.py>`_.
It keeps its procedures in a normal SimProcedure catalog called ``linux_kernel``
and adds them to the library, then adds several syscall number mappings,
including separate mappings for ``mips-o32``, ``mips-n32``, and ``mips-n64``.

In order for syscalls to be supported in the first place, the project's SimOS
must inherit from :py:class:`~bisa.simos.userland.SimUserland`, itself a SimOS
subclass. This requires the class to call SimUserland's constructor with a
super() call that includes the ``syscall_library`` keyword argument, specifying
the specific SimSyscallLibrary that contains the appropriate procedures and
mappings for the operating system. Additionally, the class's
``configure_project`` must perform a super() call including the ``abi_list``
keyword argument, which contains the list of ABIs that are valid for the current
architecture. If the ABI for the syscall can't be determined by just the syscall
number, for example, that amd64 linux programs can use either ``int 0x80`` or
``syscall`` to invoke a syscall and these two ABIs use overlapping numbers, the
SimOS cal override ``syscall_abi()``, which takes a SimState and returns the
name of the current syscall ABI. This is determined for int80/syscall by
examining the most recent jumpkind, since libVEX will produce different syscall
jumpkinds for the different instructions.

Calling conventions for syscalls are a little weird right now and they ought to
be refactored. The current situation requires that ``bisa.SYSCALL_CC`` be a map
of maps ``{arch_name: {os_name: cc_cls}}``, where ``os_name`` is the value of
project.simos.name, and each of the calling convention classes must include an
extra method called ``syscall_number`` which takes a state and return the
current syscall number. Look at the bottom of `calling_conventions.py
<https://github.com/bisa/bisa/blob/master/bisa/calling_conventions.py>`_ to
learn more about it. Not very object-oriented at all...

As a side note, each syscall is given a unique address in a special object in
CLE called the "kernel object". Upon a syscall, the address for the specific
syscall is set into the state's instruction pointer, so it will show up in the
logs. These addresses are not hooked, they are just used to identify syscalls
during analysis given only an address trace. The test for determining if an
address corresponds to a syscall is ``project.simos.is_syscall_addr(addr)`` and
the syscall corresponding to the address can be retrieved with
``project.simos.syscall_from_addr(addr)``.

Case 1, in-tree development
^^^^^^^^^^^^^^^^^^^^^^^^^^^

SimSyscallLibraries are stored in the same place as the normal SimLibraries,
``bisa/procedures/definitions``. These libraries don't have to specify any
common name, but they can if they'd like to show up in ``SIM_LIBRARIES`` for
easy access.

The same thing about adding procedures to existing catalogs of dynamic library
functions also applies to syscalls - implementing a linux syscall is as easy as
writing the SimProcedure and dropping the implementation into
``bisa/procedures/linux_kernel``. As long as the class name matches one of the
names in the number-to-name mapping of the SimLibrary (all the linux syscall
numbers are included with recent releases of bisa), it will be used.

To add a new operating system entirely, you need to implement the SimOS as well,
as a subclass of SimUserland. To integrate it into the tree, you should add it
to the ``simos`` directory, but this is not a magic directory like
``procedures``. Instead, you should add a line to ``bisa/simos/__init__.py``
calling ``register_simos()`` with the OS name as it appears in
``project.loader.main_object.os`` and the SimOS class. Your class should do
everything described above.

Case 2, out-of-tree development, tight integration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You can add syscalls to a SimSyscallLibrary the same way you can add functions
to a normal SimLibrary, by tweaking the entries in ``bisa.SIM_LIBRARIES``. If
you're this for linux you want ``bisa.SIM_LIBRARIES['linux'][0].add(name,
proc_cls)``.

You can register a SimOS with bisa from out-of-tree as well - the same
``register_simos`` method is just sitting there waiting for you as
``bisa.simos.register_simos(name, simos_cls)``.

Case 3, out-of-tree development, loose integration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The SimSyscallLibrary the SimOS uses is copied from the original during setup,
so it is safe to mutate. You can directly fiddle with
``project.simos.syscall_library`` to manipulate an individual project's
syscalls.

You can provide a SimOS class (not an instance) directly to the ``Project``
constructor via the ``simos`` keyword argument, so you can specify the SimOS for
a project explicitly if you like.

SimData
-------

What about when there is an import dependency on a data object? This is easily
resolved when the given library is actually loaded into memory - the relocation
can just be resolved as normal. However, when the library is not loaded (for
example, ``auto_load_libs=False``, or perhaps some dependency is simply
missing), things get tricky. It is not possible to guess in most cases what the
value should be, or even what its size should be, so if the guest program ever
dereferences a pointer to such a symbol, emulation will go off the rails.

CLE will warn you when this might happen:

.. code-block::

   [22:26:58] [cle.backends.externs] |  WARNING: Symbol was allocated without a known size; emulation will fail if it is used non-opaquely: _rtld_global
   [22:26:58] [cle.backends.externs] |  WARNING: Symbol was allocated without a known size; emulation will fail if it is used non-opaquely: __libc_enable_secure
   [22:26:58] [cle.backends.externs] |  WARNING: Symbol was allocated without a known size; emulation will fail if it is used non-opaquely: _rtld_global_ro
   [22:26:58] [cle.backends.externs] |  WARNING: Symbol was allocated without a known size; emulation will fail if it is used non-opaquely: _dl_argv

If you see this message and suspect it is causing issues (i.e. the program is
actually introspecting the value of these symbols), you can resolve it by
implementing and registering a SimData class, which is like a SimProcedure but
for data. Simulated data. Very cool.

A SimData can effectively specify some data that must be used to provide an
unresolved import symbol. It has a number of mechanisms to make this more
useful, including the ability to specify relocations and subdependencies.

Look at the SimData :py:class:`cle.backends.externs.simdata.SimData` class
reference and the `existing SimData subclasses
<https://github.com/bisa/cle/tree/master/cle/backends/externs/simdata>`_ for
guidelines on how to do this.
