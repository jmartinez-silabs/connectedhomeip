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
TC-SRP-1.1: SRP Client - Discovery of Infrastructure Router via RA

Verifies that a Wi-Fi DUT implementing SRP client functionality correctly
discovers an infrastructure DNS-SD service provider via IPv6 Router
Advertisements with the DNS-SD infrastructure flag.
"""

import logging

from mobly import asserts

from matter.testing.decorators import async_test_body
from matter.testing.matter_testing import MatterBaseTest, TestStep
from matter.testing.runner import default_matter_test_main

log = logging.getLogger(__name__)


class TC_SRP_1_1(MatterBaseTest):
    def desc_TC_SRP_1_1(self) -> str:
        return "[TC-SRP-1.1] SRP Client: Discovery of Infrastructure Router via RA"

    def pics_TC_SRP_1_1(self) -> list[str]:
        return ["MCORE.SRP.CLIENT"]

    def steps_TC_SRP_1_1(self) -> list[TestStep]:
        return [
            TestStep("1", "Commission DUT to TH fabric over Wi-Fi",
                     "DUT is commissioned and on the Wi-Fi network",
                     is_commissioning=True),
            TestStep("2", "TH sends an IPv6 Router Advertisement with DNS-SD infrastructure "
                     "flag set and Router Lifetime > 0",
                     "DUT receives the RA"),
            TestStep("3", "Wait for DUT to process RA",
                     "Verify DUT identifies the TH as an Infrastructure Router provider"),
            TestStep("4", "Verify DUT attempts SRP registration with TH",
                     "DUT sends an SRP DNS UPDATE to the TH address"),
        ]

    @async_test_body
    async def test_TC_SRP_1_1(self):
        # Step 1: Commission DUT
        self.step("1")
        # TODO: Commission the DUT to the TH fabric over Wi-Fi.
        # This step depends on the specific commissioning flow available.
        log.info("Commission DUT to TH fabric over Wi-Fi")

        # Step 2: Send Router Advertisement with infrastructure flag
        self.step("2")
        # TODO: The TH must send an IPv6 RA with:
        #   - Router Lifetime > 0
        #   - DNS-SD infrastructure service flag set (per draft-tlmk-infra-dnssd-01)
        #
        # This requires a platform-specific RA sender. For test environments,
        # tools like radvd or scapy can be used to craft custom RAs.
        log.info("Sending RA with DNS-SD infrastructure flag - requires platform RA sender implementation")
        asserts.skip("RA sender not yet implemented - requires platform-specific tooling")

        # Step 3: Wait for DUT to process RA
        self.step("3")
        # TODO: Query the DUT (via a diagnostic interface or by observing behavior)
        # to verify it has identified the TH as an Infrastructure Router provider.

        # Step 4: Verify SRP registration attempt
        self.step("4")
        # TODO: The TH SRP server should receive an SRP DNS UPDATE from the DUT
        # containing the DUT's service records (SRV, TXT, AAAA).


if __name__ == "__main__":
    default_matter_test_main()
