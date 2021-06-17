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
        port = "8890"  # hard-coded it for now, will change later
        # the keylime-agent uuid is system-uuid
        uuid = utils.execute('dmidecode', '-s', 'system-uuid')
        # get the node ip address
        if self.agent.advertise_address is None:
            self.agent.set_agent_advertise_addr()
        ip = self.agent.advertise_address
        LOG.debug('{"keylime_agent_uuid": %s, "ip": %s, \
            "keylime_agent_port": %s}', uuid, ip, port)
        return {"keylime_agent_uuid": uuid,
                "ip": ip,
                "keylime_agent_port": port}
