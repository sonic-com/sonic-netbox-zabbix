import functools
from pprint import pformat

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

    def __del__(self):
        self.log.info("Starting SonicNetboxZabbix_Zabbix instance deletion")
        self.api.logout()
        self.log.info("Done with SonicNetboxZabbix_Zabbix instance deletion")

    @functools.cache
    def get_hosts_all(self):
        return self.api.host.get(
            selectTags=["tag", "value"],
            selectInheritedTags=["tag", "value"],
            selectHostGroups=["groupid", "name"],
            selectMacros=["macro", "value", "description", "type"],
            selectParentTemplates=["templateid", "name"],
        )

    @functools.cache
    def get_hosts_discovered(self):
        return self.api.host.get(
            filter={"flags": 4},
            selectTags=["tag", "value"],
            selectInheritedTags=["tag", "value"],
            selectHostGroups=["groupid", "name"],
            selectMacros=["macro", "value", "description", "type"],
            selectParentTemplates=["templateid", "name"],
        )

    @functools.cache
    def get_hosts_notdiscovered(self):
        return self.api.host.get(
            filter={"flags": 0},
            selectTags=["tag", "value"],
            selectInheritedTags=["tag", "value"],
            selectHostGroups=["groupid", "name"],
            selectMacros=["macro", "value", "description", "type"],
            selectParentTemplates=["templateid", "name"],
        )

    @functools.cache
    def hostgroup_site_get_or_create(self, name):
        sites = self.api.hostgroup.get(
            filter={"name": name},
        )
        self.log.info(f"DEBUG:sites:{name}:{sites}")
        if len(sites) >= 1:
            self.log.info(f"DEBUG:sites[0]:{sites[0]}")
            groupid = sites[0]["groupid"]
        else:
            self.log.info(f"TRACE:create group:{name}")
            groupid = self.api.hostgroup.create(name=name)

        self.log.info(f"DEBUG:returning groupid:{groupid}")
        return {"groupid": groupid}

    def host_update_tags(self, hostid, tags):
        response = self.api.host.update(hostid=hostid, tags=tags)
        self.log.info(f"DEBUG: response: {pformat(response)}")
        return response

    def host_update_inventory(self, hostid, inventory):
        response = self.api.host.update(hostid=hostid, inventory=inventory)
        self.log.info(f"DEBUG: response: {pformat(response)}")
        return response

    def host_update_macros(self, hostid, macros):
        response = self.api.host.update(hostid=hostid, macros=macros)
        self.log.info(f"DEBUG: response: {pformat(response)}")
        return response

    def host_update_hostgroups(self, hostid, hostgroups):
        self.log.info(f"TRACE:hostid={hostid},hostgroups={hostgroups}")
        response = self.api.host.update(hostid=hostid, groups=hostgroups)
        self.log.info(f"DEBUG: response: {pformat(response)}")
        return response
