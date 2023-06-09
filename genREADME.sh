#!/bin/sh

if [ -z "${ANSIBLE_V}" ]; then
  ANSIBLE_V="$(grep min_ansible_version meta/main.yml | awk '{print $NF}' | tr -d '\"')"
fi

if [ -x "$(command -v ansible-playbook-grapher)" ]; then
  # https://github.com/haidaraM/ansible-playbook-grapher
  ansible-playbook-grapher -i '127.0.0.1,' -o './images/ansible-role-hardening' --include-role-tasks tests/test.yml
fi

{
echo "# Hardening - the Ansible role

An [Ansible](https://www.ansible.com/) role to make a AlmaLinux, Debian, or
Ubuntu server a bit more secure.
[systemd edition](https://freedesktop.org/wiki/Software/systemd/).

Requires Ansible >= ${ANSIBLE_V}.

Available on
[Ansible Galaxy](https://galaxy.ansible.com/konstruktoid/hardening).

[AlmaLinux 8](https://wiki.almalinux.org/release-notes/#almalinux-8),
[AlmaLinux 9](https://wiki.almalinux.org/release-notes/#almalinux-9),
[Debian 11](https://www.debian.org/releases/bullseye/),
Ubuntu [20.04 LTS (Focal Fossa)](https://releases.ubuntu.com/focal/) and
[22.04 LTS (Jammy Jellyfish)](https://releases.ubuntu.com/jammy/) are supported.

> **Note**
>
> Do not use this role without first testing in a non-operational environment.

> **Note**
>
> There is a [SLSA](https://slsa.dev/) artifact present under the
> [slsa action workflow](https://github.com/konstruktoid/ansible-role-hardening/actions/workflows/slsa.yml)
> for verification.

## Dependencies

None.

## Examples

### Playbook

\`\`\`yaml
---
- hosts: localhost
  any_errors_fatal: true
  tasks:
    - name: Include the hardening role
      ansible.builtin.include_role:
        name: konstruktoid.hardening
...
\`\`\`

### ansible-pull with git checkout

\`\`\`yaml
---
- hosts: localhost
  any_errors_fatal: true
  tasks:
    - name: Install git
      become: true
      ansible.builtin.package:
        name: git
        state: present

    - name: Checkout konstruktoid.hardening
      become: true
      ansible.builtin.git:
        repo: 'https://github.com/konstruktoid/ansible-role-hardening'
        dest: /etc/ansible/roles/konstruktoid.hardening
        version: master

    - name: Include the hardening role
      ansible.builtin.include_role:
        name: konstruktoid.hardening
...
\`\`\`

## Note regarding UFW firewall rules

Instead of resetting \`ufw\` every run and by doing so causing network traffic
disruption, the role deletes every \`ufw\` rule without
\`comment: ansible managed\` task parameter and value.



## Task Execution and Structure

See [STRUCTURE.md](STRUCTURE.md) for tree of the role structure.

## Role testing

See [TESTING.md](TESTING.md).
"
echo '## Role Variables with defaults'

for variables in $(find ./defaults -type f | sort); do
  echo; echo "### $variables"
  echo
  echo '```yaml'
  grep -vE '^#|---|\.\.\.' "$variables"
  echo '```'
done

echo
echo "## Recommended Reading

[Comparing the DISA STIG and CIS Benchmark values](https://github.com/konstruktoid/publications/blob/master/ubuntu_comparing_guides_benchmarks.md)

[Center for Internet Security Linux Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

[Common Configuration Enumeration](https://nvd.nist.gov/cce/index.cfm)

[DISA Security Technical Implementation Guides](https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=operating-systems%2Cunix-linux)

[SCAP Security Guides](https://static.open-scap.org/)

[Security focused systemd configuration](https://github.com/konstruktoid/hardening/blob/master/systemd.adoc)

## Contributing

Do you want to contribute? Great! Contributions are always welcome,
no matter how large or small. If you found something odd, feel free to submit a
issue, improve the code by creating a pull request, or by
[sponsoring this project](https://github.com/sponsors/konstruktoid).

## License

Apache License Version 2.0

## Author Information

[https://github.com/konstruktoid](https://github.com/konstruktoid \"github.com/konstruktoid\")"
} > ./README.md

{
echo "# Testing

## Distribution boxes used by Molecule and Vagrant
"

echo '```console'
git grep -E 'box:|box =' Vagrantfile molecule/ | awk '{print $NF}' |\
  tr -d '"' | sort | uniq
echo '```'

echo
echo "## Test examples
"

echo
echo "### tox environments
"
echo '```console'
tox -l
echo '```'
} > ./TESTING.md

rm ./*.log ./*.html ./*.list

{
echo "# Task Execution and Structure

## Tasks
![Task execution order](./images/ansible-role-hardening.svg)

## Structure
"

echo '```sh'
tree .
echo '```'
} > ./STRUCTURE.md
