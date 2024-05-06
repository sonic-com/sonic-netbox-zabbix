# sonic-netbox-zabbix

Pull netbox tags into zabbix host tags:
- "Zabbix nopage" -> sonic-alert-routing:nopage

Add servers, add templates to server, etc.

Don't delete servers or remove templates from them...
But do notify about things it wants to remove...

New netbox custom fields:
- zabbix host_id (for linking back, verifying exists in zabbix, etc)
- zabbix templates
  - autopopulate custom field choices with SOC* templates?

Mapping of netbox tags to zabbix templates.
