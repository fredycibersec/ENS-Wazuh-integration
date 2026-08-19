# ENS Controls Mapping — Wazuh

Full reference mapping between ENS (Real Decreto 311/2022) controls and Wazuh SCA checks and detection rules.

Every check and rule below is also tagged with its equivalent ISO/IEC 27001:2022 Annex A control — see [`iso27001_mapping.md`](iso27001_mapping.md) for the full ENS ↔ ISO 27001 correspondence table and the `compliance.iso_27001` / `ISO27001_<control>` filters.

| ENS Control | Description | Level | SCA Check IDs (Linux) | SCA Check IDs (Windows) | Rule IDs | Type |
|-------------|-------------|-------|-----------------------|-------------------------|----------|------|
| **op.acc.1** | Identificación | Básico | 30001–30006 | — | 100200, 100201 | SCA + Rules |
| **op.acc.2** | Requisitos de acceso | Básico | 30010–30014 | 31010, 31011 | 100210 | SCA + Rules |
| **op.acc.3** | Segregación de funciones | Básico | 30020–30022 | 31034 | 100220, 100221 | SCA + Rules |
| **op.acc.4** | Gestión de derechos de acceso | Básico | — | — | 100230–100233 | Rules |
| **op.acc.6** | Autenticación (usuarios org.) | Básico/Medio | 30030–30035 | 31030, 31032, 31033, 31035, 31036 | 100200–100203 | SCA + Rules |
| **op.acc.7** | Acceso remoto | Medio | 30040–30042 | — | — | SCA |
| **op.exp.2** | Configuración de seguridad | Básico/Medio | 30100–30108 | 31102 | — | SCA |
| **op.exp.3** | Gestión de la configuración | Básico | — | — | 100300–100302 | Rules |
| **op.exp.5** | Gestión de cambios | Básico | — | — | 100300, 100301 | Rules |
| **op.exp.6** | Protección frente a código dañino | Básico | 30110 | 31100, 31101 | 100310 | SCA + Rules |
| **op.exp.7** | Gestión de incidentes | Básico | — | — | 100320, 100321 | Rules |
| **op.exp.8** | Registro de actividad de usuarios | Básico/Medio | 30120–30126 | 31120, 31121, 31200 | 100330, 100331 | SCA + Rules |
| **op.exp.9** | Registro de gestión de incidentes | Básico | — | — | 100320 | Rules |
| **op.exp.10** | Protección de registros | Medio | 30123, 30130, 30131 | — | 100331, 100340 | SCA + Rules |
| **op.mon.1** | Detección de intrusión | Básico | 30200, 30201 | 31031 | 100400, 100401 | SCA + Rules |
| **mp.com.2** | Protección de la confidencialidad | Medio | 30300, 30301 | 31302 | 100500 | SCA + Rules |
| **mp.com.3** | Autenticidad e integridad | Básico | 30310 | — | 100202, 100500 | SCA + Rules |
| **mp.com.4** | Segregación de redes | Básico | 30320–30325 | — | — | SCA |
| **mp.eq.2** | Bloqueo de puesto de trabajo | Básico | 30400 | 31400 | — | SCA |
| **mp.info.3** | Cifrado de la información | Medio | 30500 | — | — | SCA |
| **mp.info.9** | Copias de seguridad | Básico | 30510 | — | — | SCA |
| **mp.s.2** | Protección de servicios web | Básico | 30600–30602 | — | 100600, 100601 | SCA + Rules |
| **mp.s.3** | Protección frente a DoS | Básico | 30320, 30324 | — | — | SCA |
| **mp.sw.2** | Aceptación y puesta en servicio | Básico | 30700 | 31700 | — | SCA |

## Controls requiring manual evidence

The following ENS controls cannot be automatically audited by Wazuh and require manual documentation, evidence collection, or process review:

| ENS Control | Description | Notes |
|-------------|-------------|-------|
| org.1 | Política de seguridad | Document required |
| org.2 | Normativa de seguridad | Document required |
| org.3 | Procedimientos de seguridad | Document required |
| org.4 | Proceso de autorización | Process + records required |
| op.pl.1 | Análisis de riesgos | Risk assessment document |
| op.pl.2 | Arquitectura de seguridad | Architecture document |
| op.acc.5 | Autenticación (usuarios externos) | MFA/PKI configuration review |
| op.cont.1 | Análisis de impacto | BIA document |
| op.cont.2 | Plan de continuidad | BCP document |
| op.cont.3 | Pruebas periódicas | Test records |
| op.ext.1 | Contratación y SLAs | Contract review |
| mp.if.1–7 | Protección de instalaciones | Physical audit |
| mp.per.1–5 | Gestión del personal | HR process review |
| mp.si.1–5 | Protección de soportes | Physical media audit |
| mp.info.1 | Datos de carácter personal | RGPD/DPO review |
| mp.info.4 | Firma electrónica | PKI review |
| mp.info.5 | Sellos de tiempo | Timestamp service review |

## Level filter reference

To filter checks by ENS compliance level in OpenSearch, query the `ens-sca-checks`
index (populated by `tools/sync_sca_to_opensearch.py` — see README Phase 2):

- **Básico**: `ens.check.compliance.ens_nivel: "Básico"`
- **Medio**: `ens.check.compliance.ens_nivel: "Medio" OR "Básico"`
- **Alto**: all checks (Básico + Medio + Alto)

> **Do not filter on `data.sca.check.compliance.*` in `wazuh-alerts-*`.** Wazuh
> only writes an individual check event there on the first scan and on a
> pass/fail state change — never a full snapshot — so those fields return
> sparse, incomplete results. Only `data.sca.type: summary` (score/passed/failed
> per policy) is reliably available in `wazuh-alerts-*`; per-control detail
> requires the `ens-sca-checks` index. See [`iso27001_mapping.md`](iso27001_mapping.md#filtering-by-iso-27001-in-opensearch).

For detection rules, filter by group (these alert normally, so `wazuh-alerts-*`
is fine here):
- `rule.groups: ENS_op.acc.*`
- `rule.groups: ENS_op.exp.*`
- `rule.groups: ENS_mp.*`
- `rule.groups: ISO27001_5.*` / `ISO27001_8.*` (equivalent ISO 27001:2022 groups)
