Flow Combiner
=============

PATHspider's flow combiner is the final stage of a plugins measurement. Once
jobs and their flow records have been merged, each flow is condensed to a
single dictionary. An array of these dictionaries is passed to the
:func:`combine_flows() <pathspider.base.Spider.combine_flows>` function.

When you are ready to start working with flow analysis, you will need to add
a new function to your plugin's class. You can see a template in the following
example:

.. code-block:: python

 class Example(SynchronizedSpider, PluggableSpider):

    def combine_flows(self, flows):
        conditions = []
        return conditions

Depending on the types of analysis you would like to do in your plugin, you
should add logic to this function to append conditions to the array.

Common patterns
---------------

A/B Connectivity Impairment Testing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Almost all plugins in the PATHspider distribution perform some variety of A/B
connectivity impairment testing. As this is a common pattern,
:func:`combine_connectivity() <pathspider.base.Spider.combine_connectivity>` is
provided to generate
these conditions. It accepts two boolean values, one for successful
connectivity of the baseline test and one for successful connectivity of the
experimental test.

If your plugin only performs a single test (as with the :class:`SingleSpider
<pathspider.single.SingleSpider>` model) you can pass only the first argument
and it will generate online or offline conditions. These will be properly
formed conditions in the namespace of your plugin, assuming you have correctly
defined your :ref:`plugin metadata <plugmeta>`.

If your plugin performs configurable tests, it may be desirable to generate
conditions based on the configuration. In this case, you can pass a third
argument to the :func:`combine_connectivity()
<pathspider.base.Spider.combine_connectivity>` function to define the prefix
for the condition. This prefix should not end with a period, for example:

.. code-block:: python

   self.combine_connectivity(True, False, prefix="dscp.48")

``pathspider.not_observed``
^^^^^^^^^^^^^^^^^^^^^^^^^^^

If the Observer did not observe a flow, usually due to too many workers being
used for the Observer to keep up, plugins in the PATHspider distribution will
add ``pathspider.not_observed`` to the conditions. In the case of
:class:`SynchronizedSpider <pathspider.sync.SynchronizedSpider>` and
:class:`DesynchronizedSpider <pathspider.desync.DesynchronizedSpider>` it is
usually possible to still determine connectivity conditions and so this does
not mean that no further conditions will be added but it can serve to add
benchmarking data inline with the measurement results.

This is not used for plugins that do not use the Observer.

Defining conditions
-------------------

Conditions take one of two forms. One form is a boolean where if it is present,
then a property of a path has been observed, but the absence of a condition
does not necessarily mean that the condition is not applicable to the path,
only that no evidence was captured for it during the test. The A/B connectivity
breakage conditions are an example of this type of condition.

The second form of condition is a condition with an attached value. Plugins in
PATHspider have used this form to, for example, record values of the DiffServ
codepoint field.

Conditions are formed of keywords seperated by periods (.) with the first
keyword being the name of the plugin, or ``pathspider`` for internal use. When a
value is attached to the condition, this is appended to the condition after a
colon (:).
