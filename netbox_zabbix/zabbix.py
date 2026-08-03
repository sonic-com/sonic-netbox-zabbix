"""Thin wrapper around the Zabbix API for the operations this tool needs."""

import functools
from pprint import pformat

from zabbix_utils import ZabbixAPI


class ZabbixClient:
    """Utils for Zabbix stuff."""

    def __init__(self, logger, configobj):
        self.log = logger
        self.config = configobj

        api = ZabbixAPI(self.config.zabbixurl)
        api.login(token=self.config.zabbixtoken)
        self.api = api

    def __del__(self):
        try:
            self.api.logout()
        except Exception:  # pragma: no cover - best-effort cleanup on teardown
            pass

    @functools.cache
    def get_hosts_all(self):
        return self.api.host.get(
            selectTags=["tag", "value"],
            selectInheritedTags=["tag", "value"],
            selectHostGroups=["groupid", "name"],
            selectMacros=["hostmacroid", "macro", "value", "description", "type"],
            selectParentTemplates=["templateid", "name"],
        )

    @functools.cache
    def get_hosts_discovered(self):
        return self.api.host.get(
            filter={"flags": 4},
            selectTags=["tag", "value"],
            selectInheritedTags=["tag", "value"],
            selectHostGroups=["groupid", "name"],
            selectMacros=["hostmacroid", "macro", "value", "description", "type"],
            selectParentTemplates=["templateid", "name"],
        )

    @functools.cache
    def get_hosts_notdiscovered(self):
        return self.api.host.get(
            filter={"flags": 0},
            selectTags=["tag", "value"],
            selectInheritedTags=["tag", "value"],
            selectHostGroups=["groupid", "name"],
            selectMacros=["hostmacroid", "macro", "value", "description", "type"],
            selectParentTemplates=["templateid", "name"],
            selectInterfaces="extend",
        )

    @functools.cache
    def hostgroup_get_or_create(self, name):
        groups = self.api.hostgroup.get(
            filter={"name": name},
        )
        self.log.debug(f"{name}:groups:{groups}")
        if len(groups) >= 1:
            self.log.debug(f"{name}:groups[0]:{groups[0]}")
            groupid = groups[0]["groupid"]
        else:
            self.log.debug(f"create group:{name}")
            groupid = self.api.hostgroup.create(name=name)["groupids"][0]

        self.log.debug(f"returning groupid:{groupid}")
        return {"groupid": int(groupid)}

    def host_sync_tags(self, hostid, existing_tags, desired_tags):
        """Update a host's tags only when the desired set actually differs.

        Zabbix has no per-tag API -- host.update(tags=...) always replaces
        the full set -- so the best selective behavior is to skip the call
        entirely when nothing changed. Comparison is order-insensitive and
        desired tags are deduped before sending.

        Returns the resulting tag list so callers can refresh their
        in-memory snapshot of the host.
        """
        seen = set()
        deduped = []
        for item in desired_tags:
            key = (item["tag"], item.get("value", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(item)

        current = {(item["tag"], item.get("value", "")) for item in existing_tags}
        if current == seen:
            self.log.debug(f"{hostid}: tags unchanged")
            return deduped

        self.log.info(f"{hostid}: updating tags")
        response = self.api.host.update(hostid=hostid, tags=deduped)
        self.log.debug(f"{hostid}:response: {pformat(response)}")
        return deduped

    def host_update_inventory(self, hostid, inventory):
        # Force inventory_mode to Automatic (1) so hosts whose inventory is
        # disabled (-1) or manual (0) accept the update instead of rejecting it.
        response = self.api.host.update(hostid=hostid, inventory_mode=1, inventory=inventory)
        self.log.debug(f"{hostid}:response: {pformat(response)}")
        return response

    def host_sync_macros(self, hostid, existing_macros, desired_macros, managed_prefixes):
        """Selectively sync the managed subset of a host's macros.

        Only macros whose name starts with one of ``managed_prefixes`` are
        created/updated/deleted to match ``desired_macros``; all other macros
        are never sent to the API. Unchanged macros generate no API call, so
        hosts don't show config churn on every run, and secret macros (whose
        values the API never returns) can't be wiped by a full rewrite.

        Returns the resulting full macro list so callers can refresh their
        in-memory snapshot of the host.
        """
        prefixes = tuple(managed_prefixes)
        result = [item for item in existing_macros if not item["macro"].startswith(prefixes)]
        current = {item["macro"]: item for item in existing_macros if item["macro"].startswith(prefixes)}

        for desired in desired_macros:
            name = desired["macro"]
            have = current.pop(name, None)
            if have is None:
                self.log.info(f"{hostid}: creating macro {name}")
                response = self.api.usermacro.create(hostid=hostid, **desired)
                self.log.debug(f"{hostid}:response: {pformat(response)}")
            elif (
                have.get("value") != desired.get("value")
                or (have.get("description") or "") != (desired.get("description") or "")
                or str(have.get("type") or 0) != str(desired.get("type") or 0)
            ):
                self.log.info(f"{hostid}: updating macro {name}")
                response = self.api.usermacro.update(hostmacroid=have["hostmacroid"], **desired)
                self.log.debug(f"{hostid}:response: {pformat(response)}")
            else:
                self.log.debug(f"{hostid}: macro {name} unchanged")
            result.append(desired)

        if current:
            self.log.info(f"{hostid}: deleting stale macros {sorted(current)}")
            response = self.api.usermacro.delete([item["hostmacroid"] for item in current.values()])
            self.log.debug(f"{hostid}:response: {pformat(response)}")

        return result

    def host_update_hostgroups(self, hostid, hostgroups):
        if self.config.verbose >= 4:
            self.log.debug(f"TRACE:{hostid}:hostgroups:{hostgroups}")
        response = self.api.host.update(hostid=hostid, groups=hostgroups)
        self.log.debug(f"{hostid}:response:{pformat(response)}")
        return response

    def host_disable(self, host):
        hostid = host["hostid"]
        if self.config.verbose >= 4:
            self.log.debug(f"TRACE:{hostid}")
        # self.log.debug(f"TRACE:host:pformat:{pformat(host)}")
        if int(host["status"]) != 1:
            self.log.warning(f"Disabling host {host['name']}/{hostid}")
            response = self.api.host.update(hostid=hostid, status=1)
            self.log.debug(f"{hostid}:response:{pformat(response)}")
            return response
        else:
            self.log.info(f"Already disabled host {host['name']}/{hostid}")
            return False

    def host_enable(self, host):
        hostid = host["hostid"]
        if self.config.verbose >= 4:
            self.log.debug(f"TRACE:{hostid}")
        if self.config.verbose >= 5:
            self.log.debug(f"TRACE:host:pformat:{pformat(host)}")
        if int(host["status"]) != 0:
            self.log.warning(f"Enabling host {host['name']}/{hostid}")
            response = self.api.host.update(hostid=hostid, status=0)
            self.log.debug(f"{hostid}:response:{pformat(response)}")
            return response
        else:
            self.log.debug(f"Already enabled host {host['name']}/{hostid}")
            return False

    def set_ipmi_interface(self, host, ipmi_ip):
        hostid = host["hostid"]
        if self.config.verbose >= 4:
            self.log.debug(f"TRACE:{hostid}")
        if self.config.verbose >= 5:
            self.log.debug(f"TRACE:host:pformat:{pformat(host)}")
