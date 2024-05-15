import functools

from zabbix_utils import ZabbixAPI


class SonicNetboxZabbix_Zabbix:
    """
    Utils for Zabbix stuff
    """

    def __init__(self, logger, config):
        self.log = logger
        self.config = config

        # self.log.info("Logging into Zabbix")
        api = ZabbixAPI(self.config.zabbixurl)
        api.login(token=self.config.zabbixtoken)
        self.api = api

    @functools.cache
    def get_hosts_all(self):
        return self.api.host.get()
