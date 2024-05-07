import pynetbox

class SonicNetboxZabbix_Netbox:
    """
    Utils for Netbox stuff
    """
    
    def __init__(self, logger, config):
        self.log = logger
        self.config = config
        
        self.log.info("Logging into Netbox")
        self.api = pynetbox.api(
            self.config.netboxurl,
            token=self.config.netboxtoken,
            threading=True,
        )
