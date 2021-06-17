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

from unittest import mock

from ironic_python_agent import agent
from ironic_python_agent.extensions import attestation
from ironic_python_agent.tests.unit import base
from ironic_python_agent import utils


class TestAttestationExtension(base.IronicAgentTest):
    def setUp(self):
        super(TestAttestationExtension, self).setUp()
        self.mock_agent = mock.Mock(spec=agent.IronicPythonAgent)
        self.agent_extension = attestation.AttestationExtension(
            agent=self.mock_agent)

    @mock.patch.object(utils, 'execute', autospec=True)
    def test_get_keylime_info(self, mock_execute):
        self.mock_agent.advertise_address = '127.0.0.1'
        mock_execute.return_value = 'uuid'
        expected_result = {'keylime_agent_uuid': 'uuid',
                           'ip': '127.0.0.1',
                           'keylime_agent_port': '8890'}
        async_result = self.agent_extension.get_keylime_info()
        async_result.join()
        self.assertFalse(self.mock_agent.set_agent_advertise_addr.called)
        mock_execute.assert_called_once_with('dmidecode', '-s', 'system-uuid')
        self.assertEqual(expected_result, async_result.command_result)
        self.assertEqual('SUCCEEDED', async_result.command_status)
