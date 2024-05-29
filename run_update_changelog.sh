#!/bin/bash

get_commits_from_last_two_merges () {
	commit_message_allowed="/develop$"
	last_two_commits_hashes=$(git log --format=%H --grep "$commit_message_allowed" -n 2)
	commits_hashes=(${last_two_commits_hashes[0]//^@/})
	most_recent_hash=${commits_hashes[0]}
	previous_hash=${commits_hashes[1]}
	pull_request_commits=$(git log --pretty=format:%s $previous_hash..$most_recent_hash)
}

is_valid_last_commit () {
	if [[ $last_commit_message =~ $commit_message_allowed ]]; then
		return 0
	fi
	return 1
}

last_commit_message=$(git log --format=%s -n 1)
commit_message_allowed="/develop$"
merged_commits_from_develop_branch=$(git log --format=oneline origin/main | grep -i -E "$commit_message_allowed" | wc -l)
pull_request_commits=()
should_add_last_changes_to_master=false

if [[ is_valid_last_commit ]]; then
	if [ "$merged_commits_from_develop_branch" -eq 1 ]; then
		pull_request_commits=$(git log --pretty=format:%s)
	else
		get_commits_from_last_two_merges
	fi
	repository_name=$1
	if [ ${#pull_request_commits[@]} -gt 0 ]; then
		python3 update_changelog.py --repository_url "${repository_name}" --pull_request_commits "${pull_request_commits[@]}"
    	if [[ $(git status --porcelain ./docs/CHANGELOG.md) ]]; then
			should_add_last_changes_to_master=true
		fi
	fi
fi
echo $should_add_last_changes_to_master
