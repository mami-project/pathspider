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

   overview
   using
   plugin
   abstract
   observer

