# sonic-netbox-zabbix #

This currently has lots of stuff hard-coded for our specific environment.
Might changes those to configurable things eventually, but for now it's more
something you can download and modify.

## Ideas of what to do ##

- Pull netbox tags into zabbix host tags:
  - "Zabbix nopage" -> sonic-alert-routing:nopage
  - Generically pull all tags in, using the slugs,
     like netbox tag: soc-restricted -> netbox-tag:soc-restricted

- Populate zabbix tags with info from netbox custom fields
  - update_group:daytime_auto -> sonic-netbox-update-group:daytime_auto

- Add servers, add templates to server, etc.

- Don't delete servers or remove templates from them...

- But maybe do notify about things it wants to remove...

- New netbox custom fields:
  - zabbix host_id (for linking back, verifying exists in zabbix, etc)
  - zabbix templates
    - autopopulate custom field choices with SOC* templates?

- Mapping of netbox tags to zabbix templates
