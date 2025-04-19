Installing bisa
===============

bisa is a library for Python 3.10+, and must be installed into a Python
environment before it can be used.

Installing from PyPI
--------------------

bisa is published on `PyPI <https://pypi.org/>`_, and using this is the easiest
and recommended way to install bisa. It can be installed bisa with pip:

.. code-block:: bash

   pip install bisa

.. tip::
   It is recommended to use an isolated python environment rather than installing
   bisa globally. Doing so reduces dependency conflicts and aids in
   reproducibility while debugging. Some popular tools that accomplish this
   include:

   * `venv <https://docs.python.org/3/library/venv.html>`_
   * `pipenv <https://pipenv.pypa.io/en/latest/>`_
   * `virtualenv <https://virtualenv.pypa.io/en/latest/>`_
   * `virtualenvwrapper <https://virtualenvwrapper.readthedocs.io/en/latest/>`_
   * `conda <https://docs.conda.io/en/latest/>`_

.. note::
   The PyPI distribution includes binary packages for most popular system
   configurations. If you are using a system that is not supported by the
   binary packages, you will need to build the C dependencies from source. See
   the `Installing from Source`_ section for more information.

Installing from Source
----------------------

bisa is a collection of Python packages, each of which is published on GitHub.
The easiest way to install bisa from source is to use `bisa-dev
<https://github.com/bisa/bisa-dev>`_.

To set up a development environment manually, first ensure that build
dependencies are installed. These consist of python development headers,
``make``, and a C compiler. On Ubuntu, these can be installed with:

.. code-block:: bash

   sudo apt-get install python3-dev build-essential

Then, checkout and install the following packages, in order:

* `archinfo <https://github.com/bisa/archinfo>`_
* `pyvex <https://github.com/bisa/pyvex>`_ (clone with ``--recursive``)
* `cle <https://github.com/bisa/cle>`_
* `claripy <https://github.com/bisa/claripy>`_
* `ailment <https://github.com/bisa/ailment>`_
* `bisa <https://github.com/bisa/bisa>`_ (``pip install`` with
  ``--no-build-isolation``)

Installing with Docker
----------------------

The bisa team maintains a container image on Docker Hub that includes bisa and
its dependencies. This image can be pulled with:

.. code-block:: bash

   docker pull bisa/bisa

The image can be run with:

.. code-block:: bash

   docker run -it bisa/bisa

This will start a shell in the container, with bisa installed and ready to use.


Troubleshooting
---------------

bisa has no attribute Project, or similar
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If bisa can be imported but the ``Project`` class is missing, it is likely one
of two problems:

#. There is a script named ``bisa.py`` in the working directory. Rename it to
   something else.
#. There is a folder called ``bisa`` in your working directory, possibly the
   cloned repository. Change the working directory to somewhere else.

AttributeError: 'module' object has no attribute 'KS_ARCH_X86'
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``keystone`` package is installed, which conflicts with the
``keystone-engine`` package, an optional dependency of bisa. Uninstall
``keystone`` and install ``keystone-engine``.
