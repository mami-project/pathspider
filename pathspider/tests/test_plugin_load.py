
import nose

import pathspider.base
import pathspider.cmd.measure

def test_plugin_load():
    try:
        # attempt to load dependencies of plugins
        import pldns
    except ImportError:
        raise nose.SkipTest

    expected_names = set(['TFO', 'ECN', 'DSCP', 'UDPZero', 'DNSResolv', 'H2', 'MSS'])
    names = set()

    for plugin in pathspider.cmd.measure.plugins:
        assert issubclass(plugin, pathspider.base.Spider)
        names.add(plugin.__name__)

    assert names == expected_names
