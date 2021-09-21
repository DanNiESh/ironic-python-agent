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

import shutil
import tempfile
from unittest import mock

from oslo_concurrency import processutils

from ironic_python_agent import agent
from ironic_python_agent import errors
from ironic_python_agent.extensions import attestation
from ironic_python_agent.tests.unit import base
from ironic_python_agent import utils


@mock.patch.object(utils, 'execute', autospec=True)
@mock.patch.object(tempfile, 'mkdtemp', lambda *_: '/tmp/tmp_dir')
@mock.patch.object(shutil, 'rmtree', lambda *_: None)
class TestAttestationExtension(base.IronicAgentTest):
    def setUp(self):
        super(TestAttestationExtension, self).setUp()
        self.mock_agent = mock.Mock(spec=agent.IronicPythonAgent)
        self.agent_extension = attestation.AttestationExtension(
            agent=self.mock_agent)
        self.tmp_dir = '/tmp/tmp_dir'

    @mock.patch('configparser.ConfigParser.read', autospec=True)
    @mock.patch('configparser.ConfigParser.has_option', autospec=True)
    @mock.patch('configparser.ConfigParser.get', autospec=True)
    def test_get_keylime_info(self, mock_cpget,
                              mock_cpoption, mock_cpread, mock_execute):
        mock_cpread.return_value = None
        mock_cpoption.return_value = True
        mock_cpget.return_value = '9002'

        mock_execute.side_effect = [
            ('0x00000001\n', ''),  # get genesis_tpm_handle
            ('', ''),  # tpm2_readpublic
            ('uuid_hash_ek ' + self.tmp_dir + '/tpm_ek', ''),  # get hash_ek
        ]
        self.mock_agent.advertise_address = agent.Host('127.0.0.1', 9990)

        expected_exec = [
            mock.call("tpm2_getcap handles-persistent | head -1"
                      + " | sed 's/- //g'", shell=True),
            mock.call('tpm2_readpublic', '-c', '0x00000001',
                      '-o', self.tmp_dir + '/tpm_ek', '-f', 'pem'),
            mock.call('sha256sum', self.tmp_dir + '/tpm_ek')
        ]

        expected_result = {'keylime_agent_uuid': 'uuid_hash_ek',
                           'keylime_agent_ip': '127.0.0.1',
                           'keylime_agent_port': '9002'}

        async_result = self.agent_extension.get_keylime_info()
        async_result.join()

        mock_cpread.assert_called_once()
        mock_cpoption.assert_called_once()
        mock_cpget.assert_called_once()
        mock_execute.assert_has_calls(expected_exec, any_order=False)
        self.assertFalse(self.mock_agent.set_agent_advertise_addr.called)
        self.assertEqual(expected_result, async_result.command_result)
        self.assertEqual('SUCCEEDED', async_result.command_status)

    @mock.patch('configparser.ConfigParser.read', autospec=True)
    @mock.patch('configparser.ConfigParser.has_option', autospec=True)
    @mock.patch('configparser.ConfigParser.get', autospec=True)
    def test_get_keylime_info_port_error(
            self,
            mock_cpget,
            mock_cpoption,
            mock_cpread,
            mock_execute):
        mock_cpread.side_effect = errors.CommandExecutionError('read error')
        async_result = self.agent_extension.get_keylime_info()
        async_result.join()
        self.assertEqual('FAILED', async_result.command_status)
        self.assertFalse(mock_cpoption.called)
        self.assertFalse(mock_cpget.called)

    @mock.patch('configparser.ConfigParser.read', autospec=True)
    @mock.patch('configparser.ConfigParser.has_option', autospec=True)
    @mock.patch('configparser.ConfigParser.get', autospec=True)
    def test_get_keylime_info_uuid_error(
            self,
            mock_cpget,
            mock_cpoption,
            mock_cpread,
            mock_execute):
        mock_cpread.return_value = None
        mock_cpoption.return_value = True
        mock_cpget.return_value = '9002'
        mock_execute.side_effect = [
            ('0x00000001\n', ''),  # get genesis_tpm_handle
            ('', ''),  # tpm2_readpublic
            processutils.ProcessExecutionError(
                stderr='get hash_ek error')  # get hash_ek
        ]
        async_result = self.agent_extension.get_keylime_info()
        async_result.join()
        self.assertEqual('FAILED', async_result.command_status)

    @mock.patch('configparser.ConfigParser.read', autospec=True)
    @mock.patch('configparser.ConfigParser.has_option', autospec=True)
    @mock.patch('configparser.ConfigParser.get', autospec=True)
    def test_get_keylime_info_ip_error(
            self,
            mock_cpget,
            mock_cpoption,
            mock_cpread,
            mock_execute):
        mock_cpread.return_value = None
        mock_cpoption.return_value = True
        mock_cpget.return_value = '9002'

        mock_execute.side_effect = [
            ('0x00000001\n', ''),  # get genesis_tpm_handle
            ('', ''),  # tpm2_readpublic
            ('uuid_hash_ek ' + self.tmp_dir + '/tpm_ek', ''),  # get hash_ek
        ]
        # set the ip to None
        self.mock_agent.advertise_address = agent.Host(None, None)

        expected_exec = [
            mock.call("tpm2_getcap handles-persistent | head -1"
                      + " | sed 's/- //g'", shell=True),
            mock.call('tpm2_readpublic', '-c', '0x00000001',
                      '-o', self.tmp_dir + '/tpm_ek', '-f', 'pem'),
            mock.call('sha256sum', self.tmp_dir + '/tpm_ek')
        ]

        async_result = self.agent_extension.get_keylime_info()
        async_result.join()

        mock_cpread.assert_called_once()
        mock_cpoption.assert_called_once()
        mock_cpget.assert_called_once()
        mock_execute.assert_has_calls(expected_exec, any_order=False)
        self.assertFalse(self.mock_agent.set_agent_advertise_addr.called)
        self.assertEqual('FAILED', async_result.command_status)
