# Canonical Ubuntu 20.04 LTS Security Technical Implementation Guide

This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. 

Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil."

## How to run

```
#  without bastion
inspec exec canonical-ubuntu-20.04-lts-stig-baseline \
  -t ssh://ubuntu@<IP> \
  -i <PATH_TO_SSH_KEY> \
  --sudo \
  --reporter=cli json:/tmp/output.json \

# with bastion
 inspec exec canonical-ubuntu-20.04-lts-stig-baseline \
--sudo \
--bastion-host=<HOST_IP>
--bastion-user=ubuntu \
-i <PATH_TO_SSH_KEY> \
-t ssh://ubuntu@<IP> \
--reporter=cli "json:/tmp/output.json"

```

## Create checklist

Install `inspec_tools` gem https://github.com/mitre/inspec_tools

```
inspec_tools inspec2ckl -j /tmp/output.json -o /tmp/output.ckl
