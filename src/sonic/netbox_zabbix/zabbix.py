import functools
from pprint import pformat

from zabbix_utils import ZabbixAPI


class SonicNetboxZabbix_Zabbix:
    """
    Utils for Zabbix stuff
    """

    log = False
    config = False

    def __init__(self, logger, configobj):
        global log
        global config

        self.log = logger
        self.config = configobj

        log = self.log
        config = self.config

        # self.log.info("Logging into Zabbix")
        api = ZabbixAPI(self.config.zabbixurl)
        api.login(token=self.config.zabbixtoken)
        self.api = api

    def __del__(self):
        self.api.logout()

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
        log.debug(f"{name}:sites:{sites}")
        if len(sites) >= 1:
            log.debug(f"{name}:sites[0]:{sites[0]}")
            groupid = sites[0]["groupid"]
        else:
            if config.verbose >= 4:
                log.debug(f"TRACE:create group:{name}")
            groupid = self.api.hostgroup.create(name=name)["groupids"][0]

        log.debug(f"returning groupid:{groupid}")
        return {"groupid": int(groupid)}

    def host_update_tags(self, hostid, tags):
        response = self.api.host.update(hostid=hostid, tags=tags)
        log.debug(f"{hostid}:response: {pformat(response)}")
        return response

    def host_update_inventory(self, hostid, inventory):
        response = self.api.host.update(hostid=hostid, inventory=inventory)
        log.debug(f"{hostid}:response: {pformat(response)}")
        return response

    def host_update_macros(self, hostid, macros):
        response = self.api.host.update(hostid=hostid, macros=macros)
        log.debug(f"{hostid}:response: {pformat(response)}")
        return response

    def host_update_hostgroups(self, hostid, hostgroups):
        if config.verbose >= 4:
            log.debug(f"TRACE:{hostid}:hostgroups:{hostgroups}")
        response = self.api.host.update(hostid=hostid, groups=hostgroups)
        log.debug(f"{hostid}:response:{pformat(response)}")
        return response

    def host_disable(self, host):
        hostid = host["hostid"]
        if config.verbose >= 4:
            log.debug(f"TRACE:{hostid}")
        # log.debug(f"TRACE:host:pformat:{pformat(host)}")
        if int(host["status"]) != 1:
            log.warning(f"Disabling host {host['name']}/{hostid}")
            response = self.api.host.update(hostid=hostid, status=1)
            log.debug(f"{hostid}:response:{pformat(response)}")
            return response
        else:
            log.info(f"Already disabled host {host['name']}/{hostid}")
            return False

    def host_enable(self, host):
        hostid = host["hostid"]
        if config.verbose >= 4:
            log.debug(f"TRACE:{hostid}")
        if config.verbose >= 5:
            log.debug(f"TRACE:host:pformat:{pformat(host)}")
        if int(host["status"]) != 0:
            log.warning(f"Enabling host {host['name']}/{hostid}")
            response = self.api.host.update(hostid=hostid, status=0)
            log.debug(f"{hostid}:response:{pformat(response)}")
            return response
        else:
            log.debug(f"Already enabled host {host['name']}/{hostid}")
            return False
