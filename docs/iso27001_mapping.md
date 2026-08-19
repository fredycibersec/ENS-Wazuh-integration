# ENS ↔ ISO/IEC 27001:2022 Controls Mapping

Correspondence between ENS (Real Decreto 311/2022) safeguards and the Annex A
controls of ISO/IEC 27001:2022 (93 controls: **5.x** Organizational, **6.x**
People, **7.x** Physical, **8.x** Technological), for use alongside
[`controls_mapping.md`](controls_mapping.md) in this project.

## Methodology and sources

CCN-CERT (Centro Criptológico Nacional) publishes an official mapping between
ENS and ISO/IEC 27001:2022 in **CCN-STIC-825 "Anexo Independiente: Mapeo
entre la Norma ISO 27001:2022 y el RD 311/2022 (ENS)"**. That PDF blocks
automated/bot fetches, so it could not be pulled directly while building this
table — if you can access it manually, please compare and correct any
divergence.

This table was instead built by combining two sources:

1. A published ENS ↔ ISO/IEC 27001:**2013** comparative table (based on the
   same CCN-STIC-825 methodology — one control column matched against the
   other), covering every ENS Anexo II measure.
2. The **official ISO/IEC 27002:2022 Annex B correspondence table**, which
   maps every ISO/IEC 27001:2013 Annex A control to its 2022 equivalent
   (controls were consolidated from 114 to 93 and renumbered/regrouped into
   5.x/6.x/7.x/8.x).

Chaining (1) → (2) gives ENS → ISO 27001:2013 → ISO 27001:2022. Where the
CCN-STIC-825-based source gave several 2013 controls for one ENS measure, the
one or two most representative 2022 controls were kept. A few 2022 controls
(8.23 Web filtering, 8.26 Application security requirements) did not exist in
2013 and were added where the ENS measure clearly requires them (e.g.
`mp.s.2`).

**As with the official guide, this is not a mathematical equivalence** —
implementing the ISO control does not automatically satisfy the ENS measure
(or vice versa) at every compliance level; treat it as a cross-reference to
avoid duplicated audit effort, not a substitute for the ENS Anexo II text.

## Compatibility note: Wazuh's own native ISO 27001 module uses 2013 numbering

Wazuh added a native "ISO 27001" module to its dashboard
([wazuh-dashboard-plugins#8286](https://github.com/wazuh/wazuh-dashboard-plugins/pull/8286)),
independent of this project. Its control catalog
(`plugins/main/common/compliance-requirements/iso27001-requirements.ts`) and
the `iso_27001` tags on Wazuh's own bundled SCA policies for third-party
software (nginx, mysql, apache, mongodb, sqlserver, iis, oracle, postgres,
macOS, debian, sles) use **ISO/IEC 27001:2013** numbering (`A.5`–`A.18`, e.g.
`A.9.2.1`), not the **2022** numbering (`5`–`8`, e.g. `5.16`) used throughout
this file and this project's `iso_27001` compliance tags. That module also
only reads `rule.compliance.iso_27001` from detection-rule alerts — it never
looks at SCA check data, so it does not conflict with or duplicate this
project's SCA-level tagging.

If you ever run this project alongside Wazuh's native module on the same
installation, expect to see two differently-numbered "ISO 27001" views —
that is a real version difference, not a bug in either one.

## Controls with automated SCA checks / detection rules

These are the ENS controls this project already audits via SCA policies
and/or `rules/ens_detection_rules.xml`. Each SCA check now carries an
`iso_27001` compliance tag, and each detection rule carries an
`ISO27001_<control>` group, alongside the existing `ens` / `ENS_<control>`
tags.

| ENS Control | Description | ISO 27001:2022 (Anexo A) tagged | SCA/Rules |
|---|---|---|---|
| **op.acc.1** | Identificación | 5.16 Identity management | SCA + Rules |
| **op.acc.2** | Requisitos de acceso | 5.15 Access control | SCA + Rules |
| **op.acc.3** | Segregación de funciones | 5.3 Segregation of duties | SCA + Rules |
| **op.acc.4** | Gestión de derechos de acceso | 5.18 Access rights | Rules |
| **op.acc.6** | Autenticación (usuarios org.) | 8.5 Secure authentication | SCA + Rules |
| **op.acc.7** | Acceso remoto | 6.7 Remote working | SCA |
| **op.exp.2** | Configuración de seguridad | 8.9 Configuration management | SCA |
| **op.exp.3** | Gestión de la configuración | 8.9 Configuration management | Rules |
| **op.exp.5** | Gestión de cambios | 8.32 Change management | Rules |
| **op.exp.6** | Protección frente a código dañino | 8.7 Protection against malware | SCA + Rules |
| **op.exp.7** | Gestión de incidentes | 5.26 Response to information security incidents | Rules |
| **op.exp.8** | Registro de actividad de usuarios | 8.15 Logging | SCA + Rules |
| **op.exp.9** | Registro de gestión de incidentes | 5.28 Collection of evidence | Rules |
| **op.exp.10** | Protección de registros | 8.15 Logging | SCA + Rules |
| **op.mon.1** | Detección de intrusión | 8.16 Monitoring activities | SCA + Rules |
| **mp.com.2** | Protección de la confidencialidad | 8.24 Use of cryptography | SCA + Rules |
| **mp.com.3** | Autenticidad e integridad | 8.24 Use of cryptography | SCA + Rules |
| **mp.com.4** | Segregación de redes | 8.22 Segregation of networks | SCA |
| **mp.eq.2** | Bloqueo de puesto de trabajo | 8.1 User endpoint devices | SCA |
| **mp.info.3** | Cifrado de la información | 8.24 Use of cryptography | SCA |
| **mp.info.9** | Copias de seguridad | 8.13 Information backup | SCA |
| **mp.s.2** | Protección de servicios web | 8.26 Application security requirements | SCA + Rules |
| **mp.s.3** | Protección frente a DoS | 8.6 Capacity management | SCA |
| **mp.sw.2** | Aceptación y puesta en servicio | 8.29 Security testing in development and acceptance | SCA |

## Controls requiring manual evidence (both frameworks)

Same set as in `controls_mapping.md` — not auditable by Wazuh, but mapped
here for ISMS documentation cross-reference. A control may map to several
ISO controls; the most representative is listed first.

| ENS Control | Description | ISO 27001:2022 (Anexo A / clause) |
|---|---|---|
| org.1 | Política de seguridad | 5.2 Information security roles and responsibilities; 5.31 Legal, statutory, regulatory and contractual requirements |
| org.2 | Normativa de seguridad | 5.1 Policies for information security; 5.6; 5.10; 5.14; 5.19; 5.24; 5.36 |
| org.3 | Procedimientos de seguridad | 5.37 Documented operating procedures; 5.5; 5.14; 5.24; 5.32; 5.36 |
| org.4 | Proceso de autorización | 5.2 Information security roles and responsibilities; 8.1; 8.19; 8.20; 8.32 |
| op.pl.1 | Análisis de riesgos | Clause 6.1.2 / 8.2–8.3 (risk assessment — not an Annex A control) |
| op.pl.2 | Arquitectura de seguridad | 5.9 Inventory of information and other associated assets; 8.20; 8.27 |
| op.acc.5 | Autenticación (usuarios externos) | 5.17 Authentication information; 8.5 Secure authentication |
| op.cont.1 | Análisis de impacto | 5.29 Information security during disruption |
| op.cont.2 | Plan de continuidad | 5.29; 5.30 ICT readiness for business continuity |
| op.cont.3 | Pruebas periódicas | 5.30 ICT readiness for business continuity |
| op.ext.1 | Contratación y SLAs | 5.19 Information security in supplier relationships; 5.20; 5.21 |
| mp.if.1 | Áreas separadas y con control de acceso | 7.1 Physical security perimeters; 7.2; 7.3; 7.8 |
| mp.if.2 | Identificación de las personas | 7.2 Physical entry |
| mp.if.3 | Acondicionamiento de los locales | 7.11 Supporting utilities; 7.12 Cabling security |
| mp.if.4 | Energía eléctrica | 7.11 Supporting utilities |
| mp.if.5 | Protección frente a incendios | 7.5 Protecting against physical and environmental threats |
| mp.if.6 | Protección frente a inundaciones | 7.5 Protecting against physical and environmental threats |
| mp.if.7 | Registro de entrada y salida de equipamiento | 7.9 Security of assets off-premises |
| mp.per.1 | Caracterización del puesto de trabajo | 6.1 Screening |
| mp.per.2 | Deberes y obligaciones | 6.2 Terms and conditions of employment; 6.5; 6.6; 5.11 |
| mp.per.3 | Concienciación | 6.3 Information security awareness, education and training |
| mp.per.4 | Formación | 6.3 Information security awareness, education and training |
| mp.per.5 | Personal alternativo | 8.14 Redundancy of information processing facilities |
| mp.si.1 | Etiquetado | 5.13 Labelling of information; 7.10 Storage media |
| mp.si.2 | Criptografía | 7.10 Storage media; 8.24 Use of cryptography |
| mp.si.3 | Custodia | 7.10 Storage media |
| mp.si.4 | Transporte | 7.9 Security of assets off-premises; 7.10 Storage media |
| mp.si.5 | Borrado y destrucción | 7.14 Secure disposal or re-use of equipment; 7.10 |
| mp.info.1 | Datos de carácter personal | 5.34 Privacy and protection of PII |
| mp.info.4 | Firma electrónica | 8.24 Use of cryptography; 8.26 |
| mp.info.5 | Sellos de tiempo | 8.26 Application security requirements |

## Filtering by ISO 27001 in OpenSearch

- **Per-control detail (recommended):** query the `ens-sca-checks` index —
  `ens.check.compliance.iso_27001: "8.24"`. This index is populated by
  `tools/sync_sca_to_opensearch.py` polling the Wazuh API for a full snapshot
  of every check on every run, so it always reflects the current state of all
  96 checks. Use the `ens_sca_checks_dashboard.ndjson` dashboard (README
  Phase 2) — it has dedicated ISO 27001 panels (compliance % by control,
  per-control detail, per-agent drill-down, and an ENS↔ISO 27001 crosswalk
  table).
- **Do not** filter on `data.sca.check.compliance.iso_27001` in
  `wazuh-alerts-*`: Wazuh only writes an individual check event there on the
  first scan or when that check's result changes, never a full snapshot, so
  results will be sparse and inconsistent depending on the time range. This
  is also why those panels were removed from the main `ens_dashboard.ndjson`.
- Detection rules: `rule.groups: ISO27001_8.24` (or `ISO27001_5.*`,
  `ISO27001_8.*` wildcards for a whole family) — these query `wazuh-alerts-*`
  safely, since rule-triggered alerts are indexed normally, not subject to
  the SCA check-event sparsity issue above.

## Maintenance

When adding a new SCA check or detection rule, tag it with both `ens` /
`ENS_<control>` **and** `iso_27001` / `ISO27001_<control>`, using this table
to pick the equivalent. If CCN-CERT's own CCN-STIC-825 mapping becomes
accessible, prefer it over the values here and update this file accordingly.
