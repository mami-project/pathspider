
class BaseChain:
    def new_flow(self, rec, ip):
        raise NotImplementedError("Cannot create a new flow with an abstract Observer chain")
