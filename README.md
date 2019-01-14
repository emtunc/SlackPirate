# SlackPirate - Slack Enumeration and Extraction Tool

[![Build Status](https://travis-ci.com/emtunc/SlackPirate.svg?branch=master)](https://travis-ci.com/emtunc/SlackPirate)

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
  * Pinned messages across all Channels
  * References to links and URLs that could provide further access to sensitive materials - think: Google Docs, Trello Invites, links to internal systems, etc
  * Files which could contain sensitive information such as .key, .sh, the words "password" or "secret" embedded in a document, etc

## Slack Cookie

The Slack web application uses a number of cookies - the one of special interest is called, wait for it... `d`. This `d` cookie  is the same across all Workspaces the victim has access to. What this means in reality is that a single stolen `d` cookie would allow an attacker to get access to all of the Workspaces the victim is logged-in to; my experience with the Slack web application is that once you are logged in, you'll remain logged in indefinitely.

## Slack Token

The Slack API token is a per-workspace token. One token cannot (as far as I know) access other workspaces in the same way the `d` cookie above allows access to all Workspaces.

For the tool to search for and extract information, you will need to provide it an API token. There are two straight forward ways of doing this:

  * Provide the tool a `d` cookie by using the `--cookie` flag. The tool will output the associated Workspaces and tokens
  * Provide the tool with a token directly by using the `--token` flag. You can find this by viewing the source of the Workspace URL and doing a search for `XOX`

The token will look something like this:

`
api_token: "xoxs-x-x-x-x"
`

Make a copy of that and pass that in to the script using the `--token` flag.

## Building

The script has been developed, tested and confirmed working on Python 3.5, 3.6 and 3.7. A quick test on Python 2 presented some compatibility issues.

#### Linux with virtualenv

  * `git clone https://github.com/emtunc/SlackPirate`
  * `pip install virtualenv`
  * `virtualenv SlackPirate`
  * `source SlackPirate/bin/activate`
  * `pip install -r requirements.txt`
  * `./SlackPirate.py --help`

#### Linux without virtualenv

  * `git clone https://github.com/emtunc/SlackPirate`
  * `chmod +x SlackPirate.py`
  * `pip install -r requirements.txt`
  * `./SlackPirate.py --help`

#### Windows with virtualenv

  * `git clone https://github.com/emtunc/SlackPirate`
  * `pip install virtualenv`
  * `virtualenv SlackPirate`
  * `SlackPirate\Scripts\activate.bat`
  * `pip install -r requirements.txt`
  * `python SlackPirate.py --help`

#### Windows without virtualenv

  * `git clone https://github.com/emtunc/SlackPirate`
  * `pip install -r requirements.txt`
  * `python SlackPirate.py --help`

## Usage

 ```./SlackPirate.py --help```
 
  * Display the help menu - this includes information about all scan modules you can explicitly select or ignore

 ```./SlackPirate.py --cookie <cookie>```
 
This will do the following:
  * Find any associated Workspaces that can be accessed using that cookie
  * Connect to any Workspaces that were returned
  * Look for API Tokens in each returned Workspace
  * Print to standard output for use in the next command

```./SlackPirate.py --token <token>```
    
This will do the following:
  * Check Token validity and only continue if Slack returns `True`
  * Print to standard output if the token supplied has admin, owner or primary_owner privileges
  * Print to standard output if the tool found any @domains that can be used to register for the Slack Workspace (you may be surprised by what you find here - if you're lucky you'll find an old, unused, registerable domain here)
  * Dump team access logs in .json format if the token provided is a privileged token
  * Dump the user list in .json format
  * Find references to S3 buckets
  * Find references to passwords and other credentials
  * Find references to AWS keys
  * Find references to private keys
  * Find references to pinned messages across all Slack channels
  * Find references to interesting URLs and links
  * Lastly, the tool will attempt to download files based on pre-defined keywords

```./SlackPirate.py --token <token> --s3-scan```
    
  * This will instruct the tool to only run the S3 scan

```./SlackPirate.py --token <token> --no-s3-scan```
    
  * This will instruct the tool to run all scans apart from the S3 scan

## Screenshots

![Alt text](screenshots/SlackPirate%20--cookie.png?raw=true "Using the --cookie flag")

![Alt text](screenshots/SlackPirate%20--token.png?raw=true "Using the --token flag")

## Join the conversation

A public Slack Workspace has been set-up where anyone can join and discuss new features, changes, feature requests or simply ask for help. Here's the invite link: 

https://join.slack.com/t/slackpirate/shared_invite/enQtNTIyNjMxNDUyMzc0LTkzY2RkNGRlYTFiNWQ4OTYxMjYyZDRjZTAxZmEyNzAwZWVkYmVmZjk2MzJmYWQ5ODI4MmYxNmQyNDk2OTQ3MTQ
