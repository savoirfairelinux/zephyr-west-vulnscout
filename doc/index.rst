zephyr-west-vulnscout
=====================

zephyr-west-vulnscout is a West extension command for Zephyr that generates
SPDX 3 Software Bills of Materials (SBOMs) and connects your builds to
VulnScout's vulnerability management workflow. Import component inventories,
scan for vulnerabilities, review product impact, and automate policy checks
without leaving your West workspace.

VulnScout and the Zephyr integration
------------------------------------

VulnScout is an open-source platform for investigating software vulnerabilities
and tracking assessments.
Its web interface and command-line tools work with the same stored inventory,
findings, and assessment data. VulnScout runs in a Docker or Podman container.

This extension uses Zephyr's ``west spdx`` command to generate SBOMs and
provides West commands for importing them and working with stored results.
A project groups a product's data, while variants distinguish board targets,
build configurations, or releases. You choose the project and variant names
when importing a build.

See the `official VulnScout repository
<https://github.com/savoirfairelinux/vulnscout>`_ for source code and releases,
and the `VulnScout documentation <https://vulnscout.readthedocs.io/en/latest/>`_
for the platform's capabilities, web interface, and assessment guidance.

From Zephyr build to assessment
-------------------------------

The integration follows five stages:

.. image:: https://raw.githubusercontent.com/savoirfairelinux/vulnscout/main/doc/source/_static/vulnscout-pipeline.svg
   :alt: Import, Enrich, Assess, Enforce, and Share, with optional AI assistance during assessment.
   :target: https://vulnscout.readthedocs.io/en/latest/vulnscout-workflow.html

* **Import:** Generate a build's SBOM and import it with ``west vulnscout add``.
  See :doc:`sbom-generation`.
* **Enrich:** Run vulnerability scanners with ``scan`` and update metadata for
  recorded findings with ``refresh``.
  See :doc:`vulnerability-scanning` and :doc:`vulnerability-data`.
* **Assess:** Open the web interface with ``serve`` to investigate findings and
  record product-specific assessments. See :doc:`interactive-mode`.
* **Enforce:** Evaluate stored findings with ``match-condition`` and use its
  exit status in CI. See :doc:`monitor-vulnerabilities`.
* **Share:** Generate reports with ``report`` and export enriched SBOMs or
  OpenVEX assessments with ``export``. See :doc:`reports` and :doc:`exports`.

Scanning identifies candidate vulnerabilities. Assessments record whether
those findings affect a particular product variant. The optional AI assistance
shown in the diagram is a VulnScout feature with separate configuration,
not a West command.

``add`` handles SBOM generation and import. The other data commands use stored
results, so you can rescan, refresh, assess, and share a build's data without
regenerating its SBOM. The stages are a logical workflow rather than a required
command order. In CI, generate needed reports and exports before the final
policy check so a matching condition does not prevent artifact creation.

Where to start
--------------

Follow :doc:`getting-started` to register the extension in your West workspace,
then :doc:`sbom-generation` to import your first build. Use
:doc:`container-configuration` for persistent data, image selection, and
wrapper mode.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   getting-started
   sbom-generation
   vulnerability-scanning
   monitor-vulnerabilities
   vulnerability-data
   interactive-mode
   exports
   reports
   templates
   container-configuration
   maintainer-and-patches
   license
