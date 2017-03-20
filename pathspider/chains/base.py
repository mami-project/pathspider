"""
.. module:: pathspider.chains.base
   :synopsis: An abstract flow observer chain

This module contains the abstract chain class which should be subclassed by
implementations of flow analysis chains for PATHspider's Observer.

.. codeauthor:: Iain R. Learmonth <irl@fsfe.org>

"""

class Chain:
    """
    This is an abstract flow analysis chain. It is intended that all flow
    analysis chains will subclass this class and it is not intended for this
    class to be directly used by PATHspider plugins.
    """

    def new_flow(self, rec, ip):
        """
        This function is called for every new flow to initialise a flow record
        with the fields that will be used by this chain. It is recommended to
        initialise all fields to None until other functions have set values for
        them to make clear which fields are set by this chain and to avoid key
        errors later.

        :param rec: the flow record
        :type rec: dict
        :param ip: the IP or IPv6 packet that triggered the creation of a new
                   flow record
        :type ip: plt.ip or plt.ip6
        """

        raise NotImplementedError("Cannot create a new flow with an abstract Observer chain")
