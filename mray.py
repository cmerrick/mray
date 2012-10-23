#!/usr/bin/python

import oauth2
from optparse import OptionParser
import sys
import imaplib
import simplejson as json
import re
import email
import os 
import math
from statlib import stats

def SetupOptionParser():
    parser = oauth2.SetupOptionParser()
    parser.add_option('--generate_refresh_token',
                      action='store_true',
                      dest='generate_refresh_token',
                      help='extra endpoint to trigger a refresh token-based generation')
    parser.add_option('--list_experiments',
                      action='store_true',
                      dest='list_experiments',
                      help='Analyze the account and list folders that are eligible for analysis.')
    parser.add_option('--analyze_experiment',
                      action='store_true',
                      dest='analyze_experiment',
                      help='Analyzes the experiment with the given name')
    parser.add_option('--experiment_name',
                      default=None,
                      help='The name of the experiment to analyze')
    
    return parser

def ListExperiments(user, auth_string):
    """Authenticates to IMAP with the given auth_string.    

    Args:
    user: The Gmail username (full email address)
    auth_string: A valid OAuth2 string, as returned by GenerateOAuth2String.
    Must not be base64-encoded, since imaplib does its own base64-encoding.
    """
    print
    imap_conn = imaplib.IMAP4_SSL('imap.gmail.com')
#    imap_conn.debug = 4
    imap_conn.authenticate('XOAUTH2', lambda x: auth_string)
    typ, data = imap_conn.list(pattern='*')
    experiments = [parse_list_response(line) for line in data if filter_folders(line)]
    print "The following folders have child folders, which make them eligible for analysis:"
    print "\t" + "\t".join(str(name) for (flag, delim, name) in experiments)

list_response_pattern = re.compile(r'\((?P<flags>.*?)\) "(?P<delimiter>.*)" (?P<name>.*)')
flags_has_children_pattern = re.compile(r'\\HasChildren')
name_not_system_folder_pattern = re.compile(r'\[Gmail\]')

def parse_list_response(line):
    flags, delimiter, name = list_response_pattern.match(line).groups()
    name = name.strip('"')
    return (flags, delimiter, name)

def filter_folders(line):
    """Filter for finding folders that might be experiments
    """
    flags, delimiter, name = list_response_pattern.match(line).groups()
    name = name.strip('"')
    return flags_has_children_pattern.search(flags) and not name_not_system_folder_pattern.match(name)

def AnalyzeExperiment(user, auth_string, experiment_name):
    """Authenticates to IMAP with the given auth_string.
    
    Args:
    user: The Gmail username (full email address)
    auth_string: A valid OAuth2 string, as returned by GenerateOAuth2String.
    experiment_name: The name of the experiment, corresponding to the name of the parent folder of the experiment
    Must not be base64-encoded, since imaplib does its own base64-encoding.
    """
    print
    imap_conn = imaplib.IMAP4_SSL('imap.gmail.com')
#    imap_conn.debug = 4
    imap_conn.authenticate('XOAUTH2', lambda x: auth_string)
    typ, data = imap_conn.list(directory=experiment_name)
    folders = [parse_list_response(line) for line in data]
    variations = [name for flag, delim, name in folders if name != experiment_name]

    if len(variations) != 2:
        raise Exception('Only analysis of two variations is supported')

    stats = []
    for variation in variations:
        print variation
        imap_conn.select(variation)
        typ, data = imap_conn.search(None,'ALL')
        messages = []
        for num in data[0].split():
            typ, data = imap_conn.fetch(num,'(RFC822)')
            messages.append(email.message_from_string(data[0][1]))

        trials = [message for message in messages if not message.has_key('In-Reply-To')]
        conversions = [message for message in messages if message.has_key('In-Reply-To')]

        mean, stdev = binomial_mean_stdev(len(trials), len(conversions))

        if mean <= 0:
            raise Exception("Cannot analyze variation with zero conversion rate")

        stats.append((variation, mean, stdev))
        print "\tTrials: {0}".format(len(trials))
        print "\tConversions: {0}".format(len(conversions))
        print "\tMean: {0}".format(mean)
        print "\tStdev: {0}".format(stdev)
    
    print "Treating {0} as the control group".format(stats[0][0])
    analyze_variations(stats[0], stats[1])


def analyze_variations(control, variation):
    observation = variation[1] - control[1]
    stdev = math.sqrt(control[2] + variation[2])
    z = observation/stdev
    print "\t Standard Deviation of {0}, observation at {1}, corresponding to a Z-score of {2}".format(stdev, observation, z)
    two_tail_prob = stats.zprob(abs(z)) - stats.zprob(-abs(z))
    print "\t Confidence: {0}".format(two_tail_prob)

def binomial_mean_stdev(trials, conversions):
    mean = float(conversions)/float(trials)
    stdev = (mean * (1 - mean))/float(trials)
    return (mean, stdev)

def main(argv):
    settings_file_name = os.path.expanduser('~/.mray')
    options_parser = SetupOptionParser()
    settings = {}
    try:
        settings_file = open(settings_file_name, "r")
        settings_text = settings_file.read()
        settings = json.loads(settings_text)
        options_parser.set_defaults(access_token=settings['access_token'],
                                    refresh_token=settings['refresh_token'])
#                                    client_id=settings['client_id'],
#                                    client_secret=settings['client_secret'])
    except IOError as e:
        pass
                   
    (options, args) = options_parser.parse_args()

    if options.generate_refresh_token:
        oauth2.RequireOptions(options, 'client_id', 'client_secret')
        response = oauth2.RefreshToken(options.client_id, options.client_secret,
                                options.refresh_token)
        print 'Access Token: %s' % response['access_token']
        print 'Access Token Expiration Seconds: %s' % response['expires_in']
        settings['access_token'] = response['access_token']
        settings_file = open(settings_file_name, "w+")
        settings_file.write(json.dumps(settings))
    elif options.list_experiments:
        oauth2.RequireOptions(options, 'user', 'access_token')
        ListExperiments(options.user,
                    oauth2.GenerateOAuth2String(options.user, options.access_token,
                                                base64_encode=False))
    elif options.analyze_experiment:
        oauth2.RequireOptions(options, 'user', 'access_token', 'experiment_name')
        AnalyzeExperiment(options.user,
                          oauth2.GenerateOAuth2String(options.user, options.access_token,
                                                 base64_encode=False),
                          options.experiment_name)
    elif options.generate_oauth2_token:
        oauth2.RequireOptions(options, 'client_id', 'client_secret')
        print 'To authorize token, visit this url and follow the directions:'
        print '  %s' % oauth2.GeneratePermissionUrl(options.client_id, options.scope)
        authorization_code = raw_input('Enter verification code: ')
        response = oauth2.AuthorizeTokens(options.client_id, options.client_secret,
                                   authorization_code)
        print 'Refresh Token: %s' % response['refresh_token']
        print 'Access Token: %s' % response['access_token']
        print 'Access Token Expiration Seconds: %s' % response['expires_in']
        settings['access_token'] = response['access_token']
        settings['refresh_token'] = response['refresh_token']
        settings_file = open(settings_file_name, "w+")
        settings_file.write(json.dumps(settings))
    else:
        options_parser.print_help()
        print 'Nothing to do, exiting.'
    return

if __name__ == '__main__':
  main(sys.argv)
