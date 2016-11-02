Welcome to PATHspider's documentation!
======================================

In today's Internet we see an increasing deployment of middleboxes. While
middleboxes provide in-network functionality that is necessary to keep networks
manageable and economically viable, any packet mangling — whether essential for
the needed functionality or accidental as an unwanted side effect — makes it
more and more difficult to deploy new protocols or extensions of existing
protocols.

For the evolution of the protocol stack, it is important to know which network
impairments exist and potentially need to be worked around. While classical
network measurement tools are often focused on absolute performance values,
PATHspider performs A/B testing between two different protocols or different
protocol extensions to perform controlled experiments of protocol-dependent
connectivity problems as well as differential treatment.

PATHspider is a framework for performing and analyzing these measurements,
while the actual A/B test can be easily customized. This documentation
describes the architecture of PATHspider, the plugins available and how to use
and develop the plugins.

Table of Contents
-----------------

.. toctree::
   :maxdepth: 2

   intro
   installation
   using
   plugins
   resolver
   plugindev
   pto_upload
   advanced
   

.. toctree::
   :hidden:

   references

Citing PATHspider
-----------------

When presenting work that uses PATHspider, we would appreciate it if you could
cite PATHspider as:

    Learmonth, I.R., Trammell, B., Kuhlewind, M. and Fairhurst, G., 2016, July.
    `PATHspider: A tool for active measurement of path transparency
    <https://mami-project.eu/wp-content/uploads/2015/10/anrw16-final13.pdf>`_.
    In Proceedings of the 2016 Applied Networking Research Workshop (pp. 62-64).
    ACM.

Acknowledgements
----------------

Current development of PATHspider is supported by the European Union's Horizon
2020 project MAMI. This project has received funding from the European Union's
Horizon 2020 research and innovation programme under grant agreement No 688421.
The opinions expressed and arguments employed reflect only the authors' view.
The European Commission is not responsible for any use that may be made of that
information.
