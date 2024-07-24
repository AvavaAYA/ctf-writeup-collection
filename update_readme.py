#!/usr/bin/env python3

import os
import re
import subprocess


def parse_toml(file_path):
    result = {}
    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if "=" in line:
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"')
                result[key] = value
    return result


def get_new_readmes():
    cmd = "git diff --cached --name-only --diff-filter=A"
    output = subprocess.check_output(cmd, shell=True).decode("utf-8")
    return [
        f
        for f in output.split("\n")
        if (f.endswith("/README.md") and f.count("/") == 2)
    ]


def extract_info(readme_path):
    path = "./" + readme_path[: readme_path.index("/README.md")]

    with open(readme_path, "r") as f:
        content = f.read()

    header_match = re.search(r"---\n(.*?)\n---", content, re.DOTALL)
    if header_match:
        header = header_match.group(1)
        challenge = re.search(r"challenge:\s*(.*)", header)
        challenge = challenge.group(1) if challenge else ""

        tags = re.findall(r"- (.*)", header)
        keywords = ", ".join(tags)
    else:
        challenge = os.path.basename(os.path.dirname(readme_path))
        keywords = ""

    info_path = os.path.join(os.path.dirname(os.path.dirname(readme_path)), "info.toml")
    if os.path.exists(info_path):
        info = parse_toml(info_path)
        source = info.get("contest", "")
        link = info.get("link", "")
    else:
        source = os.path.basename(os.path.dirname(os.path.dirname(readme_path)))
        link = ""

    return source, link, challenge, path, keywords


def update_main_readme(new_entries):
    main_readme = "README.md"
    with open(main_readme, "r") as f:
        content = f.read()

    table_pattern = (
        r"(\|[\s]*Source[\s]*\|[\s]*Challenge[\s]*\|[\s]*Keywords[\s]*\|.*?)\n\n"
    )
    table_match = re.search(table_pattern, content, re.DOTALL)

    if not table_match:
        print("Failed to find table.")
        raise Exception("No table found")

    table_start = table_match.start()
    table_end = table_match.end()
    table_content = table_match.group(1).split("\n")

    existing_entries = []
    current_source = None
    current_link = None

    for row in table_content[2:]:
        if row.strip():
            parts = re.findall(r"\[(.*?)\]\((.*?)\)", row)
            if parts:
                if len(parts) >= 2:
                    source, link = parts[0]
                    challenge, path = parts[1]
                    current_source = source
                    current_link = link
                elif len(parts) == 1:
                    challenge, path = parts[0]
                    source = current_source
                    link = current_link
                keywords = row.split("|")[-2].strip()
                existing_entries.append((source, link, challenge, path, keywords))
            elif "👆" in row:
                challenge_path = re.findall(r"\[(.*?)\]\((.*?)\)", row)
                if challenge_path:
                    challenge, path = challenge_path[0]
                    keywords = row.split("|")[-2].strip()
                    existing_entries.append(
                        (current_source, current_link, challenge, path, keywords)
                    )

    for new_entry in new_entries:
        source, link, challenge, path, keywords = new_entry
        insert_index = len(existing_entries)

        for i, entry in enumerate(existing_entries):
            if entry[0] == source:
                insert_index = i + 1
                while (
                    insert_index < len(existing_entries)
                    and existing_entries[insert_index][0] == "👆"
                ):
                    insert_index += 1
                break

        if insert_index < len(existing_entries):
            existing_entries.insert(insert_index, new_entry)
        else:
            existing_entries.append(new_entry)

    updated_table = [table_content[0], table_content[1]]
    current_source = None
    for entry in existing_entries:
        source, link, challenge, path, keywords = entry
        if source == current_source:
            source_cell = "👆"
        else:
            source_cell = f"[{source}]({link})"
            current_source = source

        new_row = f"| {source_cell} | [{challenge}]({path}) | {keywords} |"
        updated_table.append(new_row)

    updated_table_content = "\n".join(updated_table)
    updated_content = (
        content[:table_start] + updated_table_content + "\n\n" + content[table_end:]
    )

    print("================Updating README================")
    print(updated_table_content)
    print("================Updating README================")

    with open(main_readme, "w") as f:
        f.write(updated_content)

    subprocess.run(["git", "add", main_readme])


def main():
    new_readmes = get_new_readmes()
    if not new_readmes:
        return

    new_entries = [extract_info(readme) for readme in new_readmes]
    update_main_readme(new_entries)


if __name__ == "__main__":
    main()
