# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from oslo_serialization import base64
import tempfile
import tarfile
import os
from oslo_concurrency import processutils
from oslo_log import log

from ironic_python_agent.extensions import base
from ironic_python_agent import utils

LOG = log.getLogger(__name__)


class AttestationExtension(base.BaseAgentExtension):
    @base.async_command('get_keylime_info')
    def get_keylime_info(self):
        """Get the uuid, ip, port of keylime-agent when it's running

        :returns: A dict contains ip, uuid, port
        """
        LOG.debug('Getting keylime agent information')
        port = '9002'

        try:
            out, _err = utils.execute('journalctl', '-u', 'keylime-agent')
            LOG.info(_err)
        except processutils.ProcessExecutionError as e:
            LOG.error('Getting keylime agent log failed with error: %s', e)
            return
        # get the keylime-agent uuid from agent log
        uuid = ''
        out = out.splitlines()
        for line in out:
            if 'Agent UUID:' in line:
                uuid = line.split(":")[-1].strip()

        # get the node ip address
        if self.agent.advertise_address is None:
            self.agent.set_agent_advertise_addr()
        ip = self.agent.advertise_address.hostname
        LOG.debug('{"keylime_agent_uuid": %s, "keylime_agent_ip": %s, \
            "keylime_agent_port": %s}', uuid, ip, port)
        return {"keylime_agent_uuid": uuid,
                "keylime_agent_ip": ip,
                "keylime_agent_port": port}

    @base.sync_command('get_keylime_attestation_files')
    def get_keylime_attestation_files(self):
        """Get the allowlist.txt file and checksum on the node

        :returns: A dict contains a gzipped and base64 encoded string
                  of the allowlist and it's checksum.
        """
        LOG.debug('Getting keylime attestation files')
        # try:
        #     # utils.execute('touch', '/root/checksum.txt')
        #     out, _err = utils.execute('sha256sum', '/root/allowlist.txt', '<', 'checksum.txt')
        #     LOG.debug('{"checksum out": %s}', out)
        #     LOG.info(_err)
        # except processutils.ProcessExecutionError as e:
        #     LOG.error('Getting allowlist checksum failed with error: %s', e)
        #     return
        files = ['/root/allowlist.txt', '/root/checksum.txt']
        file_list_encode = utils.gzip_and_b64encode(io_dict=None, file_list=files)
        # LOG.debug('{"file_list": %s}', file_list_encode)

        temp_files_gzipped = tempfile.NamedTemporaryFile()
        data = base64.decode_as_bytes(file_list_encode)
        temp_files_gzipped.write(data)
        tars = tarfile.open(temp_files_gzipped.name)
        temp_files_gzipped.close()
        tar_checksum1 = tars.extractfile('root/checksum.txt')
        tar_allowlist = tars.extractfile('root/allowlist.txt')

        os.makedirs('/root/tardir1')

        allowlist_path = os.path.join('/root/tardir1',
                                'allowlist.txt')
        try:
            with open(allowlist_path, 'wb') as f:
                f.write(tar_allowlist.read())
        except Exception as e:
            msg = ('Error write tar_allowlist: %s', e)
            LOG.exception(msg)

        checksum_path1 = os.path.join('/root/tardir1',
                                'checksum.txt')
        try:
            with open(checksum_path1, 'wb') as f:
                f.write(tar_checksum1.read())
        except Exception as e:
            msg = ('Error write tar_checksum1: %s', e)
            LOG.exception(msg)


        os.makedirs('/root/tardir2')
        checksum_path2 = os.path.join('root/tardir2',
                                'checksum.txt')


        os.makedirs('/root/tardir3')

        tar_zip_path = os.path.join('/root/tardir3',
                                'tar_zip')
        try:
            with open(tar_zip_path, 'wb') as f:
                f.write(data)
        except Exception as e:
            msg = ('Error write tar_zip_data: %s', e)
            LOG.exception(msg)

        LOG.debug('Get tarfile members:%s', tars.getmembers())
        return {'file_list': file_list_encode}

