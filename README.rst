========================
Linux KVM Inspection POC
========================

| Ever wanted to know what's going on inside that KVM virtual machine?
| Wanna use those root privileges for fun and profit?
|

This POC showcases accessing a `KVM <https://www.linux-kvm.org/>`_-powered virtual machine from the kernel using
nothing but `ftrace <https://www.kernel.org/doc/html/latest/trace/ftrace-uses.html>`_ (or any other hooking mechanism).

The kernel module reads some of the running machine's registers and scans it's memory for a given byte sequence.

Demo
~~~~

1. Run the linux host and the VM inside.
2. ``make run`` and see it can't find the search string.
3. Write the search string to the inner VM's console.
4. Re-run the module and see it finds the string successfully! *(if the demo gods will allow it)*

.. image:: https://user-images.githubusercontent.com/18242949/78300401-1b9f4180-7540-11ea-9778-c62d9f37584c.gif

Requirements and setup
~~~~~~~~~~~~~~~~~~~~~~

* GCC and Make.
* A linux host running a KVM virtual machine (e.g. with `QEMU <https://help.ubuntu.com/community/KVM/Installation>`_).

In order to run the POC with the Makefile:

* An SSH connection to the host.

The following variables are configurable in the Makefile:

+--------+----------------------------------------------------+
| NAME   | The output kernel module's name                    |
+--------+----------------------------------------------------+
| KDIR   | The kernel source directory to build with          |
|        | (usually ``/lib/modules/$(shell uname -r)/build``) |
+--------+----------------------------------------------------+
| REMOTE | The remote URI for SSH commands                    |
|        | (in the format of ``user@address``)                |
+--------+----------------------------------------------------+

The byte sequence the module searches for can be changed in `main.c <main.c>`_ via:

.. code:: c

   #define SEARCH_BYTES "..."

Build the kernel module (it will be in ``build/$(NAME).ko``):

.. code:: bash

   make build

Build and run the module on the remote host:

.. code:: bash

   make
   # or explicitly:
   make run

The `Makefile <Makefile>`_ contains some more goodies if you're interested :)

Further reading
~~~~~~~~~~~~~~~

You're welcome to read through the small `research documentation <research.rst>`_ I wrote.
