
import nose

import pathspider.run
import pathspider.base

def test_plugin_load():
    try:
        # attempt to load dependencies of plugins
        import pldns
    except ImportError:
        raise nose.SkipTest

    expected_names = set(['TFO', 'ECN', 'DSCP', 'UDPZero', 'UDPOpts'])
    names = set()

    for plugin in pathspider.run.plugins:
        assert issubclass(plugin, pathspider.base.Spider)
        names.add(plugin.__name__)

    print("Found plugins: {}".format(repr(names)))

    assert names == expected_names
