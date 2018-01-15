from pathspider.desync import DesynchronizedSpider
from pathspider.sync import SynchronizedSpider

class SingleSpider(DesynchronizedSpider):
    # pylint: disable=W0223

    connections = [SynchronizedSpider.connect]
