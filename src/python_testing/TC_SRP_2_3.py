#
#    Copyright (c) 2026 Project CHIP Authors
#    All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#

"""
TC-SRP-2.3: SRP Client - Fallback to mDNS When No Provider Available

Verifies that a Wi-Fi DUT falls back to Multicast DNS for service
advertising when no infrastructure DNS-SD service provider is available.
"""

import logging
import subprocess

from mobly import asserts

from matter.testing.decorators import async_test_body
from matter.testing.matter_testing import MatterBaseTest, TestStep
from matter.testing.runner import default_matter_test_main

log = logging.getLogger(__name__)


class TC_SRP_2_3(MatterBaseTest):
    def desc_TC_SRP_2_3(self) -> str:
        return "[TC-SRP-2.3] SRP Client: Fallback to mDNS When No Provider Available"

    def pics_TC_SRP_2_3(self) -> list[str]:
        return ["MCORE.SRP.CLIENT"]

    def steps_TC_SRP_2_3(self) -> list[TestStep]:
        return [
            TestStep("1", "Commission DUT to TH fabric on a Wi-Fi network with no "
                     "infrastructure DNS-SD provider",
                     "DUT is commissioned",
                     is_commissioning=True),
            TestStep("2", "Open commissioning window on DUT",
                     "DUT should advertise _matterc._udp via mDNS"),
            TestStep("3", "TH performs DNS-SD browse for _matterc._udp via mDNS",
                     "Verify DUT is discoverable via mDNS"),
            TestStep("4", "TH performs DNS-SD browse for _matter._tcp via mDNS",
                     "Verify DUT operational service is discoverable via mDNS"),
        ]

    @async_test_body
    async def test_TC_SRP_2_3(self):
        # Step 1: Commission DUT (no infrastructure provider on network)
        self.step("1")
        log.info("Commission DUT on Wi-Fi network without any infrastructure DNS-SD provider")
        # TODO: Commission the DUT. Ensure no SRP server/infrastructure router is present.

        # Step 2: Open commissioning window
        self.step("2")
        # TODO: Send OpenCommissioningWindow command to DUT.
        log.info("Opening commissioning window on DUT")

        # Step 3: Verify mDNS commissionable discovery
        self.step("3")
        # Use dns-sd or avahi-browse to discover the DUT's commissionable service
        log.info("Browsing for _matterc._udp via mDNS")
        # TODO: Implement mDNS browse and verify DUT is discoverable.
        # Example verification using dns-sd CLI tool:
        #   dns-sd -B _matterc._udp local.
        # Or using the Matter SDK discovery APIs.

        # Step 4: Verify mDNS operational discovery
        self.step("4")
        log.info("Browsing for _matter._tcp via mDNS")
        # TODO: Implement mDNS browse for _matter._tcp and verify DUT's
        # operational service is present with correct instance name.


if __name__ == "__main__":
    default_matter_test_main()
