
import pathspider.run
import pathspider.base

def test_plugin_load():
    expected_names = set(['TFO', 'ECN', 'TLS', 'DSCP'])
    names = set()

    for plugin in pathspider.run.plugins:
        assert issubclass(plugin, pathspider.base.Spider)
        names.add(plugin.__name__)

    print("Found plugins: {}".format(repr(names)))

    assert names == expected_names
