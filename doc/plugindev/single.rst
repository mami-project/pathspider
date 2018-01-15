SingleSpider Development
========================

SingleSpider uses the built-in connection helpers to make a single connection
to the target which is optionally observed by Observer chains.

This is the simplest model and only requires a ``combine_flows`` function to
generate conditions from the connection helper output and flow record output
from the Observer.
