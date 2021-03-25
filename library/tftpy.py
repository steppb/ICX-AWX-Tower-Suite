#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Brian Stepp <a1c_stepp@yahoo.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = """
---
module: tftpy
short_description: Download file from TFTP server.
version_added: "2.9"
author: "Brian Stepp (@steppb)"
description:
  - This module provides an interface to the tftpy library.
options:
  host:
    description:
      - IP address of the TFTP server to download from.
    type: str
    required: true
  filename:
    description:
      - File path of file on remote server.
    type: str
    required: true
  output:
    description:
      - Destination file path.
    type: str
    required: true
requirements:
  - python >= 3.6
  - tftpy >= 0.8
"""

EXAMPLES = """
- name: Download file from TFTP server
  tftpy:
    host: 172.16.1.1
"""

TFTPY_IMP_ERR = None
try:
  import tftpy
  HAS_TFTPY = True
except ImportError:
  TFTPY_IMP_ERR = traceback.format_exc()
  HAS_TFTPY = False

from ansible.module_utils.basic import AnsibleModule

def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(type='str', required=True),
            filename=dict(type='str', required=True),
            output=dict(type='str', required=True),
        )
    )

    if not HAS_TFTPY:
        module.fail_json(
            msg = missing_required_lib("tftpy"),
            exception = TFTPY_IMP_ERR
        )

    result = {'changed': False}

    host = module.params['host']
    filename = module.params['filename']
    output = module.params['output']

    client = tftpy.TftpClient(host)
    client.download(filename, output)

    module.exit_json(**result)

if __name__ == '__main__':
    main()
