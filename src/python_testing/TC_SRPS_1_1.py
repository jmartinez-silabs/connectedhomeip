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
TC-SRPS-1.1: SRP Server - Accept Service Registration

Verifies that a NIM DUT implementing SRP server functionality correctly
accepts SRP service registrations from Wi-Fi devices.
"""

import logging

from mobly import asserts

from matter.testing.decorators import async_test_body
from matter.testing.matter_testing import MatterBaseTest, TestStep
from matter.testing.runner import default_matter_test_main

log = logging.getLogger(__name__)


class TC_SRPS_1_1(MatterBaseTest):
    def desc_TC_SRPS_1_1(self) -> str:
        return "[TC-SRPS-1.1] SRP Server: Accept Service Registration"

    def pics_TC_SRPS_1_1(self) -> list[str]:
        return ["MCORE.SRP.SERVER"]

    def steps_TC_SRPS_1_1(self) -> list[TestStep]:
        return [
            TestStep("1", "Commission DUT (NIM)",
                     "DUT is commissioned and SRP server is running",
                     is_commissioning=True),
            TestStep("2", "TH sends an SRP DNS UPDATE to register a _matter._tcp service",
                     "DUT SRP server accepts the registration"),
            TestStep("3", "TH sends an SRP DNS UPDATE to update the TXT records",
                     "DUT SRP server accepts the update"),
            TestStep("4", "TH sends an SRP DNS UPDATE to remove the service",
                     "DUT SRP server removes the registration"),
        ]

    @async_test_body
    async def test_TC_SRPS_1_1(self):
        # Step 1: Commission DUT (NIM device)
        self.step("1")
        log.info("Commission DUT (Network Infrastructure Manager)")
        # TODO: Commission the DUT NIM device and verify SRP server is running.

        # Step 2: Register service via SRP
        self.step("2")
        log.info("Sending SRP DNS UPDATE to register _matter._tcp service")
        # TODO: Implement SRP client in test harness to send a DNS UPDATE
        # per RFC 9665 with:
        #   - Host AAAA record
        #   - SRV record for _matter._tcp
        #   - TXT record with test key/value pairs
        #   - Signed with test key pair
        # Verify DUT responds with a successful DNS UPDATE response (RCODE=NOERROR).
        asserts.skip("SRP client for TH not yet implemented")

        # Step 3: Update service via SRP
        self.step("3")
        log.info("Sending SRP DNS UPDATE to update TXT records")
        # TODO: Send updated DNS UPDATE with modified TXT records.
        # Verify DUT accepts the update.

        # Step 4: Remove service via SRP
        self.step("4")
        log.info("Sending SRP DNS UPDATE to remove service")
        # TODO: Send DNS UPDATE to remove the service registration.
        # Verify DUT removes the service from its zone.


if __name__ == "__main__":
    default_matter_test_main()
