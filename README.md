# sonic-netbox-zabbix #

[![Ruff](https://github.com/sonic-com/sonic-netbox-zabbix/actions/workflows/ruff.yml/badge.svg)](https://github.com/sonic-com/sonic-netbox-zabbix/actions/workflows/ruff.yml)

This currently has lots of stuff hard-coded for our specific environment.
Might changes those to configurable things eventually, but for now it's more
something you can download and modify.

## Requirements ##

- Python 3.11 or newer.
- [uv](https://docs.astral.sh/uv/) for dependency management and running.

## Installation ##

Clone the repo and let `uv` create the virtualenv and install everything from
the lockfile:

```bash
git clone https://github.com/sonic-com/sonic-netbox-zabbix
cd sonic-netbox-zabbix
uv sync
```

To install it as a standalone command (a `netbox_zabbix` executable) instead of
running it from the source tree:

```bash
uv tool install .
```

## Configuration ##

Settings can come from command-line flags or a config file. Copy the example
config and fill in your NetBox and Zabbix URLs and API tokens:

```bash
cp sonic-netbox-zabbix.example.conf sonic-netbox-zabbix.conf
$EDITOR sonic-netbox-zabbix.conf
```

Config files are read from the first of these that exists (later flags on the
command line override them):

- `/etc/sonic/netbox-zabbix.conf`
- `~/.sonic-netbox-zabbix.conf`
- `./sonic-netbox-zabbix.conf`

The config (and the matching long flags) are:

```ini
netboxurl = https://netbox.example.com/
zabbixurl = https://zabbix.example.com/zabbix/
netboxtoken = abc123_changeme_789xyz
zabbixtoken = abc123_changeme_789xyz
```

> **Note:** `sonic-netbox-zabbix*.conf` is git-ignored so your tokens don't get
> committed. Keep real secrets out of the repo.

## Running ##

From the source tree:

```bash
uv run netbox_zabbix --help
```

With a config file in place, a normal sync run is just:

```bash
uv run netbox_zabbix
```

You can also run it as a module (`uv run python -m netbox_zabbix`), or directly
as `netbox_zabbix` if you installed it with `uv tool install`.

Use `-v` (repeatable, up to `-vvv`) for more logging, `-q` for less, and the
various `--skip-*` flags to limit which kinds of data get synced. See
`--help` for the full list.

## Updating dependencies ##

Bump the locked dependencies to their latest allowed versions, sync the
virtualenv, and refresh the exported `requirements.txt`:

```bash
uv lock --upgrade
uv sync
make requirements.txt
```

To change which packages or version constraints are used, edit the
`dependencies` list in `pyproject.toml` first, then run the commands above.

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
