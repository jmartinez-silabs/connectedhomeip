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
TC-SRP-2.1: SRP Client - Service Registration with Infrastructure Provider

Verifies that a Wi-Fi DUT correctly registers its Matter DNS-SD services
(commissionable and operational) via SRP with an infrastructure provider.
"""

import logging

from mobly import asserts

from matter.testing.decorators import async_test_body
from matter.testing.matter_testing import MatterBaseTest, TestStep
from matter.testing.runner import default_matter_test_main

log = logging.getLogger(__name__)


class TC_SRP_2_1(MatterBaseTest):
    def desc_TC_SRP_2_1(self) -> str:
        return "[TC-SRP-2.1] SRP Client: Service Registration with Infrastructure Provider"

    def pics_TC_SRP_2_1(self) -> list[str]:
        return ["MCORE.SRP.CLIENT"]

    def steps_TC_SRP_2_1(self) -> list[TestStep]:
        return [
            TestStep("1", "Commission DUT to TH fabric over Wi-Fi",
                     "DUT is commissioned",
                     is_commissioning=True),
            TestStep("2", "TH sends RA with infrastructure flag",
                     "DUT discovers TH as Infrastructure Router provider"),
            TestStep("3", "Open commissioning window on DUT",
                     "DUT should register _matterc._udp service via SRP"),
            TestStep("4", "Verify SRP registration received by TH",
                     "TH receives SRP DNS UPDATE containing SRV, TXT, and AAAA records for _matterc._udp"),
            TestStep("5", "Verify operational service registration",
                     "TH receives SRP DNS UPDATE containing SRV, TXT, and AAAA records for _matter._tcp"),
        ]

    @async_test_body
    async def test_TC_SRP_2_1(self):
        # Step 1: Commission DUT
        self.step("1")
        log.info("Commission DUT to TH fabric over Wi-Fi")
        # TODO: Commission the DUT

        # Step 2: Infrastructure provider discovery
        self.step("2")
        # TODO: TH sends RA with DNS-SD infrastructure flag.
        # Wait for DUT to discover TH as provider.
        log.info("Sending RA with DNS-SD infrastructure flag")
        asserts.skip("RA sender not yet implemented - requires platform-specific tooling")

        # Step 3: Open commissioning window
        self.step("3")
        # TODO: Send OpenCommissioningWindow command to DUT.
        # The DUT should register _matterc._udp via SRP with TH.

        # Step 4: Verify commissionable service SRP registration
        self.step("4")
        # TODO: Check TH SRP server for incoming DNS UPDATE with:
        #   - SRV record for _matterc._udp
        #   - TXT record with correct Matter commissionable discovery keys
        #     (D, VP, DT, DN, CM, RI, PH, PI, SII, SAI, SAT, T, ICD)
        #   - AAAA record with DUT IPv6 address

        # Step 5: Verify operational service SRP registration
        self.step("5")
        # TODO: Check TH SRP server for DNS UPDATE with:
        #   - SRV record for _matter._tcp
        #   - TXT record with operational discovery keys (SII, SAI, SAT, T, ICD)
        #   - AAAA record with DUT IPv6 address


if __name__ == "__main__":
    default_matter_test_main()
