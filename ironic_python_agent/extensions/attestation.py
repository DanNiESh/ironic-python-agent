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

import configparser
import shutil
import tempfile
import time

from oslo_concurrency import processutils
from oslo_log import log

from ironic_python_agent import errors
from ironic_python_agent.extensions import base
from ironic_python_agent import utils

LOG = log.getLogger(__name__)


class AttestationExtension(base.BaseAgentExtension):
    @base.async_command('get_keylime_info')
    def get_keylime_info(self):
        """Get the uuid, ip, port of keylime-agent

        :returns: A dict contains ip, uuid, port
        """
        LOG.debug('Getting keylime agent information')

        # get keylime-agent's port from config file
        port = None
        try:
            config = configparser.ConfigParser()
            config.read('/etc/keylime.conf')
            if config.has_option('cloud_agent', 'cloudagent_port'):
                port = config.get(
                    'cloud_agent', 'cloudagent_port')
        except Exception as e:
            error_msg = ('Getting cloudagent_port'
                         + 'failed with an error: %s' % e)
            LOG.error(error_msg)
            raise errors.CommandExecutionError(error_msg)

        # get keylime-agent's uuid from tpm ek
        uuid = None
        try:
            cmd = "tpm2_getcap handles-persistent | head -1 | sed 's/- //g'"
            genesis_tpm_handle, _err = utils.execute(cmd, shell=True)
            LOG.debug("Get genesis_tpm_handle %s", genesis_tpm_handle)
            genesis_tpm_temp = tempfile.mkdtemp()
            LOG.debug("Get genesis_tpm_temp %s", genesis_tpm_temp)
            path_ek = genesis_tpm_temp + "/tpm_ek"
            LOG.debug("ek path is: %s", path_ek)
            utils.execute("tpm2_readpublic", "-c", genesis_tpm_handle.strip(),
                          "-o", path_ek, "-f", "pem")
            hash_ek, _err = utils.execute("sha256sum", path_ek)
            LOG.debug("Get hash_ek:%s", hash_ek)
            uuid = hash_ek.split()[0]
        except processutils.ProcessExecutionError as e:
            error_msg = ('Getting hash_ek failed with an error: %s' % e)
            LOG.error(error_msg)
            raise errors.CommandExecutionError(error_msg)
        finally:
            shutil.rmtree(genesis_tpm_temp)

        # get the node ip address
        ip = None
        if self.agent.advertise_address is None:
            self.agent.set_agent_advertise_addr()
        ip = self.agent.advertise_address.hostname

        LOG.debug('{"keylime_agent_uuid": %s, "keylime_agent_ip": %s, \
            "keylime_agent_port": %s}', uuid, ip, port)

        keylime_dict = {"keylime_agent_uuid": uuid,
                        "keylime_agent_ip": ip,
                        "keylime_agent_port": port}

        if any([v is None for v in keylime_dict.values()]):
            msg = 'Incomplete keylime agent information!'
            LOG.error(msg)
            raise errors.CommandExecutionError(msg)

        return keylime_dict
