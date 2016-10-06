
import pathspider.run
import pathspider.base

def test_plugin_load():
    names = set()

    for plugin in pathspider.run.plugins:
        assert issubclass(plugin, pathspider.base.Spider)
        names.add(plugin.__name__)

    expected_names = set(['TFO', 'ECN', 'TLS', 'DSCP', 'Template'])
    assert names == expected_names
