def get_changelog_content():
    with open('VERSION', 'r') as version_file:
        version = version_file.read().split('v')[1].strip()

    with open('./docs/CHANGELOG.md', 'r') as changelog_file:
        changelog = changelog_file.read()

    version_start = changelog.find(f"## [{version}]")

    if version_start == -1:
        print(f"Version {version} not found in the changelog.")
        return None

    version_end = changelog.find("## [", version_start + 1)

    if version_end == -1:
        version_content = changelog[version_start + 1:]
    else:
        version_content = changelog[version_start + 1:version_end]

    version_content_without_header = version_content.split('\n', 1)[1]

    return version_content_without_header


print(get_changelog_content())
