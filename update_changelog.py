# -*- coding: utf-8 -*-
# This script will update the CHANGELOG.md file based on the commits in the pull request.
# It will append a section the following template:
#
# - <Release START>
# ## [X.Y.Z] - YYYY-MM-DD <- Release Header
# ### [Category A] <-- From here until the last category is considered release content
#      - [Commit Message]
# ### [Category B]
#      - [Commit Message]
# - <Release END>
# [... Previous Releases ...]
#
# [X.Y.Z]: github.com/owner/repository/compare/vX.Y.Z..vX.Y.Z <- Changelog Footer
# [X.Y.Q]: github.com/owner/repository/compare/vX.Y.Z..vX.Y.Q

import re
import datetime
import argparse
import copy
from typing import Tuple, List, Dict
from enum import Enum


class ChangeTypes(Enum):
    breaking = 'BREAKING/'
    feat = 'FEATURE/'
    fix = 'FIX/'


class ReleaseCategories(Enum):
    added = 'Added'
    changed = 'Changed'
    fixed = 'Fixed'
    removed = 'Removed'


Version = Tuple[int, int, int]
VersionToChangeTypeMap = Dict[ChangeTypes, Version]
version_change_types_regex = rf'^({ChangeTypes.breaking.value}|{ChangeTypes.feat.value}|{ChangeTypes.fix.value})'


def define_file_arguments() -> argparse.Namespace:
    arguments_dictionary = {
        'repository_url': {'help': 'remote repository url'},
        'pull_request_commits': {'help': 'pull request commits'}
    }
    parser = argparse.ArgumentParser()
    for arg_name, arg_value in arguments_dictionary.items():
        parser.add_argument('--{}'.format(arg_name), **arg_value)
    return parser.parse_args()


# builds a dictionary containing the formatted commits messages for each category
def create_release_dictionary_from(commits: List[str]) -> dict[ReleaseCategories, List[str]]:
    release_categories = {
        ReleaseCategories.added.value: [],
        ReleaseCategories.changed.value: [],
        ReleaseCategories.fixed.value: [],
        ReleaseCategories.removed.value: []
    }
    commit_prefix_to_category_map = {
        'ADD:': ReleaseCategories.added.value,
        'FEAT:': ReleaseCategories.added.value,
        'FEATURE:': ReleaseCategories.added.value,
        'CHANGE:': ReleaseCategories.changed.value,
        'REFACTOR:': ReleaseCategories.changed.value,
        'FIX:': ReleaseCategories.fixed.value,
        'REMOVE:': ReleaseCategories.removed.value,
    }
    for commit_prefix, category in commit_prefix_to_category_map.items():
        for commit in commits:
            category_keywords = re.compile(rf'{version_change_types_regex}?{commit_prefix}.*$', re.IGNORECASE)
            if re.search(category_keywords, commit):
                commit_message = commit.split(':', maxsplit=1)[1]
                if commit_message.strip().capitalize() not in release_categories[category]:
                    release_categories[category].append(commit_message.strip().capitalize())

    return release_categories


def is_there_version_change(commits: List[str]) -> bool:
    version_change_keywords = re.compile(rf'{version_change_types_regex}.*$', re.IGNORECASE)
    version_change_commits = [commit for commit in commits if re.match(version_change_keywords, commit)]
    return len(version_change_commits) != 0


def find_versions_from(changelog: str, commits: List[str]) -> Tuple[str, str]:
    previous_version = find_previous_version_from(changelog)
    new_version = find_new_version_from(previous_version, commits)
    return new_version, previous_version


def update_changelog(changelog: str, new_version: str, previous_version: str) -> str:
    changelog = prepend_release_header_to(changelog, new_version)
    changelog = append_footer_section_to(changelog, new_version, previous_version)
    return changelog


def transform_release_dict_to_formatted_string(release_section: dict[ReleaseCategories, List[str]]) -> str:
    content = ''
    for category, commits in sorted(release_section.items()):
        if commits:
            content += f'### {category}\n\n'
            for commit_message in commits:
                content += f'- {commit_message}.\n'
            content += '\n'
    return content


def get_release_content_index(changelog_content: str) -> Tuple[int, int]:
    latest_release_header, second_latest_release_header = get_headers_from_two_latest_releases(changelog_content)
    starting_index = changelog_content.index(latest_release_header) + len(latest_release_header)
    ending_index = changelog_content.index(second_latest_release_header)
    return starting_index, ending_index


def find_previous_version_from(changelog: str) -> str:
    # "## [X.Y.Z] -"
    release_header_version_pattern = re.compile(r'##\s\[(\d+\.\d+\.\d+)\]\s-', re.MULTILINE)
    return re.findall(release_header_version_pattern, changelog)[0]


def find_new_version_from(previous_version: str, commits: List[str]) -> str:
    version: List[int] = [int(number) for number in previous_version.split('.')]
    version_to_change_based_on_change_type: VersionToChangeTypeMap = {
        ChangeTypes.breaking: (1, 0, 0),
        ChangeTypes.feat: (0, 1, 0),
        ChangeTypes.fix: (0, 0, 1)
    }
    change_type = get_change_type_from(commits)
    default_change_type = version_to_change_based_on_change_type[ChangeTypes.fix]
    major, minor, patch = version_to_change_based_on_change_type.get(change_type, default_change_type)

    version[0] += major
    version[1] = 0 if major > 0 else version[1] + minor
    version[2] = 0 if major > 0 or minor > 0 else version[2] + patch

    return '.'.join(map(str, version))


def get_change_type_from(commits: List[str]) -> ChangeTypes:
    commits_starting_with_breaking = re.compile(r'^BREAKING/.*$', re.IGNORECASE)
    commits_containing_breaking_changes = [commit for commit in commits
                                           if re.search(commits_starting_with_breaking, commit)]
    if commits_containing_breaking_changes:
        return ChangeTypes.breaking
    commits_starting_with_feat = re.compile(r'^FEATURE/.*$', re.IGNORECASE)
    commits_containing_feat_changes = [commit for commit in commits if re.search(commits_starting_with_feat, commit)]
    if commits_containing_feat_changes:
        return ChangeTypes.feat
    return ChangeTypes.fix


# Appends to the changelog the Release Header with the following format: ## [X.Y.Z] - YYYY-MM-DD
def prepend_release_header_to(changelog: str, new_version: str) -> str:
    # "## [X.Y.Z] -"
    release_header_version_pattern = re.compile(r'##\s\[(\d+\.\d+\.\d+)\]\s-')
    today = datetime.date.today().isoformat()
    release_header_template = f'\n## [{new_version}] - {today}\n\n'
    index = re.search(release_header_version_pattern, changelog).start()
    changelog = changelog[:index - 1] + release_header_template + changelog[index:]
    return changelog


# Appends to the changelog the Footer section with the following format: [X.Y.Z]: github.com/owner/repository/compare/vX.Y.Z..vX.Y.Z
def append_footer_section_to(changelog: str, new_version: str, previous_version: str) -> str:
    # "[X.Y.Z]:"
    footer_pattern = re.compile(r'\[(\d+\.\d+\.\d+)\]:\s*')
    index = re.search(footer_pattern, changelog).start()
    footer_template = f'[{new_version}]: {FILE_ARGUMENTS.repository_url}/compare/v{new_version}..v{previous_version}\n'
    changelog = changelog[:index] + footer_template + changelog[index:]
    return changelog


def get_headers_from_two_latest_releases(changelog_content: str) -> Tuple[str, str]:
    # "## [X.Y.Z] - YYYY-MM-DD"
    release_header_pattern = re.compile(r'##\s\[(\d+\.\d+\.\d+)\]\s-\s(\d{4}-\d{2}-\d{2})')
    changelog_versions_headers = release_header_pattern.findall(changelog_content)
    new_version, new_version_date = changelog_versions_headers[0]
    previous_version, previous_version_date = changelog_versions_headers[1]
    latest_release_header = f'## [{new_version}] - {new_version_date}\n\n'
    second_latest_release_header = f'## [{previous_version}] - {previous_version_date}\n\n'

    return latest_release_header, second_latest_release_header


def update_changelog_version() -> None:
    with open('./CHANGELOG.md', 'r+') as changelog_file:
        current_changelog = copy.deepcopy(changelog_file.read())
        new_version, previous_version = find_versions_from(current_changelog, commits)
        current_changelog = update_changelog(current_changelog, new_version, previous_version)
        release_section_as_string = transform_release_dict_to_formatted_string(release_section)
        starting_index, ending_index = get_release_content_index(current_changelog)

        changelog_file.seek(starting_index)
        changelog_file.seek(ending_index)

        updated_changelog = current_changelog[:starting_index] + release_section_as_string + \
            current_changelog[ending_index:]

        changelog_file.seek(0)
        changelog_file.write(updated_changelog)
        changelog_file.close()

        with open('VERSION', 'w') as version_file:
            version_file.write(f'v{new_version}')


FILE_ARGUMENTS = define_file_arguments()
commits: List[str] = FILE_ARGUMENTS.pull_request_commits.split('\n')
release_section = create_release_dictionary_from(commits) if is_there_version_change(commits) else {}
are_there_commits_to_include = any(release_section.values())

if are_there_commits_to_include:
    update_changelog_version()
