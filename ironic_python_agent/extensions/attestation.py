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
        port = "9002"
        # the keylime-agent uuid is system-uuid
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
