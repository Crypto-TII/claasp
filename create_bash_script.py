import os
import sys


with open("docker/Dockerfile", "r") as f:
    dockerfile_lines = f.readlines()

claasp_directory = os.path.abspath(".")
bash_instructions = ["#!/bin/bash"]
environment_variables = []
docker_command = ""

for line in dockerfile_lines:
    line = line.strip()

    if line.startswith("FROM"):
        continue

    is_a_comment = line.startswith("#")
    if not line or is_a_comment:
        continue

    is_split_command = line.endswith("\\")
    if is_split_command:
        docker_command += line[:-1]
        continue

    docker_command += line

    bash_instruction = ""
    match docker_command.split()[0]:
        case "RUN":
            bash_instruction = docker_command.split("RUN")[1].strip()
        case "ENV":
            command = docker_command.split("ENV")[1].strip()
            environment_variable = command.split("=")[0]
            if environment_variable not in environment_variables:
                environment_variables.append(environment_variable)
            bash_instruction = f"export {command}"
        case "ARG":
            command = docker_command.split("ARG")[1].strip()
            bash_instruction = f"export {command}"
        case "WORKDIR":
            directory = docker_command.split("WORKDIR")[1].strip()
            if os.path.exists(directory):
                bash_instruction = f"cd {directory}"
            else:
                bash_instruction = f"mkdir {directory} && cd {directory}"
        case "COPY":
            command = docker_command.split("COPY")[1].strip()
            src, dst = command.split()
            src = f"{claasp_directory}{os.sep}{src}"
            bash_instruction = f"cp {src} {dst}"
            if os.path.isdir(src):
                bash_instruction += " -r"
        case _:
            docker_command = ""
            continue

    bash_instructions.append(bash_instruction)
    docker_command = ""


for environment_variable in environment_variables:
    bash_instructions.append(
        f"echo 'export {environment_variable}='${environment_variable} >> ~/.bashrc"
    )

with open("dependencies_script.sh", "w") as f:
    f.write("\n\n".join(bash_instructions))
