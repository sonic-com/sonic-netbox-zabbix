from pyzabbix import ZabbixAPI, ZabbixAPIException

class SonicNetboxZabbix_Zabbix:
    """
    Utils for Zabbix stuff
    """
    
    def __init__(self, logger, config):
        self.log = logger
        self.config = config

        # self.log.info("Logging into Zabbix")
        api = ZabbixAPI(self.config.zabbixurl)
        api.login(api_token=self.config.zabbixtoken)
        self.api = api
