#!/usr/bin/env python

import errno
import optparse
import sys

import ansiblelint
import ansiblelint.formatters as formatters
import six
from ansiblelint import RulesCollection
from ansiblelint.version import __version__
import yaml
import os

import requests
import json
from github import Github


def load_config(config_file):
    config_path = config_file if config_file else ".ansible-lint"

    if os.path.exists(config_path):
        with open(config_path, "r") as stream:
            try:
                return yaml.safe_load(stream)
            except yaml.YAMLError:
                pass

    return None





def post_comment(match, token, repo_name, pr_id, commit):
    url = "https://api.github.com/repos/{}/pulls/{}/reviews".format(repo_name, pr_id)
    text = "E{} |{}| {}\n".format(match.rule.id, match.rule.severity, match.message)
    data = {
      "commit_id": commit.sha,
      "body": text,
      "event": "COMMENT",
      "comments": [{
        "path": match.filename,
        "position": match.linenumber,
        "body": match.rule.description
      }]
    }
    headers = {
      "Content-Type": "application/json",
      "Authorization": "token {}".format(token)
    }
    r = requests.post(url, data=json.dumps(data), headers=headers)
    if r.status_code != 200:
        print(r.text)
    return r.status_code


def main():

    formatter = formatters.Formatter()

    parser = optparse.OptionParser("%prog [options] playbook.yml [playbook2 ...]",
                                   version="%prog " + __version__)

    parser.add_option('-L', dest='listrules', default=False,
                      action='store_true', help="list all the rules")
    parser.add_option('-q', dest='quiet',
                      default=False,
                      action='store_true',
                      help="quieter, although not silent output")
    parser.add_option('-p', dest='parseable',
                      default=False,
                      action='store_true',
                      help="parseable output in the format of pep8")
    parser.add_option('--parseable-severity', dest='parseable_severity',
                      default=False,
                      action='store_true',
                      help="parseable output including severity of rule")
    parser.add_option('-r', action='append', dest='rulesdir',
                      default=[], type='str',
                      help="specify one or more rules directories using "
                           "one or more -r arguments. Any -r flags override "
                           "the default rules in %s, unless -R is also used."
                           % ansiblelint.default_rulesdir)
    parser.add_option('-R', action='store_true',
                      default=False,
                      dest='use_default_rules',
                      help="Use default rules in %s in addition to any extra "
                           "rules directories specified with -r. There is "
                           "no need to specify this if no -r flags are used"
                           % ansiblelint.default_rulesdir)
    parser.add_option('-t', dest='tags',
                      action='append',
                      default=[],
                      help="only check rules whose id/tags match these values")
    parser.add_option('-T', dest='listtags', action='store_true',
                      help="list all the tags")
    parser.add_option('-v', dest='verbosity', action='count',
                      help="Increase verbosity level",
                      default=0)
    parser.add_option('-x', dest='skip_list', default=[], action='append',
                      help="only check rules whose id/tags do not " +
                      "match these values")
    parser.add_option('--nocolor', dest='colored',
                      default=hasattr(sys.stdout, 'isatty') and sys.stdout.isatty(),
                      action='store_false',
                      help="disable colored output")
    parser.add_option('--force-color', dest='colored',
                      action='store_true',
                      help="Try force colored output (relying on ansible's code)")
    parser.add_option('--exclude', dest='exclude_paths', action='append',
                      help='path to directories or files to skip. This option'
                           ' is repeatable.',
                      default=[])
    parser.add_option('--token', dest='token', action='store', type='string',
                      help='github token',
                      default="")
    parser.add_option('--roles_dir', dest='roles_dir', action='store', type='string',
                      help='directory where roles are located',
                      default="")
    parser.add_option('--repo_name', dest='repo_name', action='store', type='string',
                      help='name of github repo in format <owner>/<name>',
                      default="")
    parser.add_option('--pr_id', dest='pr_id', action='store', type='int',
                      help='number of pull request',
                      default=0)
    parser.add_option('--publish', dest='publish', action='store_true',
                      help='publish analysis to github',
                      default=False)
    parser.add_option('-c', help='Specify configuration file to use.  Defaults to ".ansible-lint"')
    options, args = parser.parse_args(sys.argv[1:])

    config = load_config(options.c)

    if config:
        if 'quiet' in config:
            options.quiet = options.quiet or config['quiet']

        if 'parseable' in config:
            options.parseable = options.parseable or config['parseable']

        if 'parseable_severity' in config:
            options.parseable_severity = options.parseable_severity or \
                                         config['parseable_severity']

        if 'use_default_rules' in config:
            options.use_default_rules = options.use_default_rules or config['use_default_rules']

        if 'verbosity' in config:
            options.verbosity = options.verbosity + config['verbosity']

        if 'exclude_paths' in config:
            options.exclude_paths = options.exclude_paths + config['exclude_paths']

        if 'rulesdir' in config:
            options.rulesdir = options.rulesdir + config['rulesdir']

        if 'skip_list' in config:
            options.skip_list = options.skip_list + config['skip_list']

        if 'tags' in config:
            options.tags = options.tags + config['tags']

    if options.quiet:
        formatter = formatters.QuietFormatter()

    if options.parseable:
        formatter = formatters.ParseableFormatter()

    if options.parseable_severity:
        formatter = formatters.ParseableSeverityFormatter()

    if len(args) == 0 and not (options.listrules or options.listtags):
        parser.print_help(file=sys.stderr)
        return 1

    if options.use_default_rules:
        rulesdirs = options.rulesdir + [ansiblelint.default_rulesdir]
    else:
        rulesdirs = options.rulesdir or [ansiblelint.default_rulesdir]

    rules = RulesCollection()
    for rulesdir in rulesdirs:
        rules.extend(RulesCollection.create_from_directory(rulesdir))

    if options.listrules:
        print(rules)
        return 0

    if options.listtags:
        print(rules.listtags())
        return 0

    if isinstance(options.tags, six.string_types):
        options.tags = options.tags.split(',')

    skip = set()
    for s in options.skip_list:
        skip.update(s.split(','))
    options.skip_list = frozenset(skip)

    playbooks = set(args)
    matches = list()
    checked_files = set()
    for playbook in playbooks:
        runner = ansiblelint.Runner(rules, playbook, options.tags,
                                    options.skip_list, options.exclude_paths,
                                    options.verbosity, checked_files)
        matches.extend(runner.run())

    matches.sort(key=lambda x: (x.filename, x.linenumber, x.rule.id))


    if "ROLES_DIR" in os.environ:
        options.roles_dir = options.roles_dir or os.environ["ROLES_DIR"]
    if "GITHUB_TOKEN" in os.environ:
        options.token = options.token or os.environ["GITHUB_TOKEN"]
    if "REPO_NAME" in os.environ:
        options.repo_name = options.repo_name or os.environ["REPO_NAME"]
    if "PR" in os.environ:
        try:
            options.pr_id = options.pr_id or int(os.environ["PR"])
        except:
            options.pr_id = options.pr_id
    if "PUBLISH" in os.environ:
        options.publish = options.publish or bool(os.environ["PUBLISH"])


    if config:
        if 'roles_dir' in config:
            options.roles_dir = options.roles_dir or config['roles_dir']
        if 'token' in config:
            options.token = options.token or config['token']
        if 'repo_name' in config:
            options.repo_name = options.repo_name or config['repo_name']
        if 'pr_id' in config:
            options.pr_id = options.pr_id or config['pr_id']

    commit = ""
    if options.publish:
        g = Github(options.token)
        repo = g.get_repo(options.repo_name)
        pr = repo.get_pull(options.pr_id)
        commit = pr.get_commits().reversed[0]

    for match in matches:
        if options.roles_dir in match.filename:
            match.filename = match.filename[len(options.roles_dir.rstrip("/"))+1:]
        if options.publish:
            print("publishing comment to github")
            rs = post_comment(match, options.token, options.repo_name, options.pr_id, commit)
            print(rs)
        print(formatter.format(match, options.colored))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except IOError as exc:
        if exc.errno != errno.EPIPE:
            raise
    except RuntimeError as e:
        raise SystemExit(str(e))

