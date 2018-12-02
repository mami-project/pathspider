
import nose
from nose.tools import assert_equal

import pathspider.base
import pathspider.cmd.measure

def test_plugin_load():
    try:
        # attempt to load dependencies of plugins
        import pldns
    except ImportError:
        raise nose.SkipTest

    expected_names = set(['DNSResolv', 'DSCP', 'ECN', 'EvilBit', 'H2', 'MSS',
                          'TCPOptions', 'TFO', 'UDPZero'])
    names = set()

    for plugin in pathspider.cmd.measure.plugins:
        assert issubclass(plugin, pathspider.base.Spider)
        names.add(plugin.__name__)

    assert_equal(names, expected_names)
