..  # This file is part of Vexy
    #
    # Licensed under the Apache License, Version 2.0 (the "License");
    # you may not use this file except in compliance with the License.
    # You may obtain a copy of the License at
    #
    #     http://www.apache.org/licenses/LICENSE-2.0
    #
    # Unless required by applicable law or agreed to in writing, software
    # distributed under the License is distributed on an "AS IS" BASIS,
    # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    # See the License for the specific language governing permissions and
    # limitations under the License.
    #
    # SPDX-License-Identifier: Apache-2.0
    # Copyright (c) Paul Horton. All Rights Reserved.

Vexy Documentation
====================================================

Software Bill of Materials (SBOMs) are gaining traction and are a great way to codify what dependencies
your software relies on from the Open Source ecosystems (and internal libraries too!).

The SBOM for a given release of a given piece of software should be static in terms of the components that
comprise that release.

`CycloneDX`_, in this authors view - the best Bill of Materials format, also allows for `Vulnerability
Exploitability Exchange`_ (or VEX) information to be included in your BOM.

Known vulnerabilities change over time - we always know more about the security posture of Open Source components
tomorrow than we did today. So how do we keep our BOMs updated with this information?

`CycloneDX`_ also allows for BOMs to interlink for the above reason. The best way to manage this scenario is to
generate a BOM that describes your software release, excluding VEX data, and then have a tool (perhaps `vexy`?)
produce you a VEX document (in `CycloneDX`_ format) that links back to your SBOM.

Did I confuse you? If so - read more about `Independent BOM and VEX here`_.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   install
   usage
   configuration
   data-sources
   support
   changelog


.. _CycloneDX: https://cyclonedx.org
.. _Vulnerability Exploitability Exchange: https://cyclonedx.org/capabilities/#vulnerability-exploitability-exchange-vex
.. _Independent BOM and VEX here: https://cyclonedx.org/capabilities/vex/