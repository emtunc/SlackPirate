# SlackPirate - Slack Enumeration Tool

This is a tool developed in Python which uses the native Slack APIs to extract 'interesting' information from a Slack workspace given an access token.

As of May 2018, Slack has over 8 million customers and that number is rapidly rising - the integration and 'ChatOps' possibilities are endless and allows teams (not just developers!) to create some really powerful workflows and Slack bot/application interactions.

As is the way with corporations large and small, it is not unusual for tools such as Slack to fly under the Information Security governance/policy radar which ultimately leads to precarious situations whereby sensitive and confidential information end up in places they shouldn't be.

The purpose of this tool is two-fold:

* Red-teamers can use this to identify and extract sensitive information, documents, credentials, etc from Slack given a low-privileged account to the organisation's Workspace. This could allow an attacker to pivot on to other systems and/or gain far more intimate knowledge and inner-workings of corporate systems/applications

* Blue-teamers can use this to identify and detect sensitive information on the Workspace that perhaps shouldn't exist on there in the first instance. Blue-teamers can use this information for internal training and awareness purposes by demonstrating the output of the tool and the type of 'things' that could be used and abused by (internal as well as external) attackers.

The tool allows you to easily gather sensitive information for offline viewing at your convenience.

Note: I'm a Python n00b and have no doubt that the script can be optimised and improved massively - please feel free to make pull requests; I'll review and merge them as appropriate!

## Information Gathering

The tool uses the native Slack APIs to extract 'interesting' information and looks for the following information, today:

* Print to standard output the domains (if any) that are allowed to register for the Workspace - I've seen stale, old and forgotten domains here that can be purchased and used to register for the Workspace
* Links to S3 buckets
* Passwords
* AWS Access/Secret keys
* Private Keys
* Files which could contain sensitive information such as .key, .sh, the words "password" or "secret" embedded in a document, etc

## Slack Token

For the tool to work, you need to give it an access token. This can be a low privileged, basic account all the way up to an admin/owner account; the latter will give you access to Workspace access logs which could be used by attackers for further attacks.

Slack access token types: https://api.slack.com/docs/token-types

The easiest way to grab a token is to simply browse to the Slack workspace URL (the victim will probably already be logged on to the Workspace), view-source and do a search for `xoxs`. You will see something that looks like this:

```
api_token: "xoxs-x-x-x-x"
```

Make a copy of that and pass that in to the script using the `--token` flag.

Tip: Want to know what workspaces the victim is already signed in to? Simply visit the URL of a random Workspace you know the victim won't be logged on to (like https://emtunc.slack.com) and Slack will tell you at the bottom!

## Usage

The script was developed using Python 3.7 - a quick test on Python 2 presented some compatability issues.

Tested and working on Windows 10, Ubuntu 18.04 and the latest Kali build.

### Linux with virtualenv (Recommended)

* `git clone https://github.com/emtunc/SlackPirate`
* `pip install virtualenv`
* `virtualenv SlackPirate`
* `source SlackPirate/bin/activate`
* `pip install -r requirements.txt`
* `./SlackPirate.py --token`

### Linux
* `git clone https://github.com/emtunc/SlackPirate`
* `chmod +x SlackPirate.py`
* `pip install -r requirements.txt`
* `./SlackPirate.py --token`

### Windows with virtualenv (Recommended)

* `git clone https://github.com/emtunc/SlackPirate`
* `pip install virtualenv`
* `virtualenv SlackPirate`
* `SlackPirate\Scripts\activate.bat`
* `pip install -r requirements.txt`
* `python SlackPirate.py --token`

### Windows

* `git clone https://github.com/emtunc/SlackPirate`
* `pip install -r requirements.txt`
* `python SlackPirate.py --token`


## Screenshots

