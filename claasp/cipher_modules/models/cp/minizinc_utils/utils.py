import os

def filter_out_strings_containing_substring(strings_list, substring):
    return [string for string in strings_list if substring not in string]


def group_strings_by_pattern(list_of_data):
    results = []
    data = list_of_data
    data = filter_out_strings_containing_substring(data, 'array')
    prefixes = set([entry.split("_y")[0].split(": ")[1] for entry in data if "_y" in entry])

    # For each prefix, collect matching strings
    for prefix in prefixes:
        sublist = [entry.split(": ")[1][:-1] for entry in data if
                   entry.startswith(f"var bool: {prefix}") and "_y" in entry]
        if sublist:
            results.append(sublist)

    return results

def replace_existing_file_name(file_name):
    name, extension = file_name.split('.')
    att = 0
    while os.path.exists(file_name):
        file_name = f'{name}_{att}.{extension}'
        att += 1
    return file_name