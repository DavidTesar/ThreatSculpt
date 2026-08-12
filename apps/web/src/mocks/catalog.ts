import type { ExploitMaturity, Severity } from '@/types/domain';
import { severityForCvss } from '@/lib/risk';

/**
 * The stand-in for the NVD + CISA KEV mirror the control plane syncs. Real CVE identifiers
 * and real characteristics, so the demo shows recognisable vulnerabilities rather than
 * invented ones — an executive who has read a headline about Log4Shell should see it here.
 */

export interface CatalogEntry {
  cve_id: string;
  description: string;
  cvss_base: number;
  cvss_vector: string;
  kev_listed: boolean;
  kev_due_date: string | null;
  exploit_maturity: ExploitMaturity;
  published_at: string;
  /** Which observed product this CVE attaches to, for plausible finding placement. */
  product: string;
}

export const CVE_CATALOG: readonly CatalogEntry[] = [
  {
    cve_id: 'CVE-2021-44228',
    description:
      'Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP endpoints. An attacker who can control a logged message can execute arbitrary code on the host.',
    cvss_base: 10.0,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    kev_listed: true,
    kev_due_date: '2021-12-24',
    exploit_maturity: 'weaponized',
    published_at: '2021-12-10T00:00:00Z',
    product: 'Apache Tomcat',
  },
  {
    cve_id: 'CVE-2023-44487',
    description:
      'The HTTP/2 protocol allows a denial of service because request cancellation can reset many streams quickly (Rapid Reset).',
    cvss_base: 7.5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    kev_listed: true,
    kev_due_date: '2023-10-31',
    exploit_maturity: 'weaponized',
    published_at: '2023-10-10T00:00:00Z',
    product: 'nginx',
  },
  {
    cve_id: 'CVE-2024-3094',
    description:
      'Malicious code was discovered in the upstream tarballs of xz, introducing a backdoor in the liblzma library that can allow remote unauthenticated SSH access.',
    cvss_base: 10.0,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    kev_listed: true,
    kev_due_date: '2024-04-17',
    exploit_maturity: 'poc',
    published_at: '2024-03-29T00:00:00Z',
    product: 'OpenSSH',
  },
  {
    cve_id: 'CVE-2014-0160',
    description:
      'The TLS heartbeat extension in OpenSSL does not properly handle payload length, allowing remote attackers to read process memory (Heartbleed).',
    cvss_base: 7.5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    kev_listed: true,
    kev_due_date: '2022-05-03',
    exploit_maturity: 'weaponized',
    published_at: '2014-04-07T00:00:00Z',
    product: 'OpenSSL',
  },
  {
    cve_id: 'CVE-2017-0144',
    description:
      'The SMBv1 server in Microsoft Windows allows remote code execution via crafted packets (EternalBlue).',
    cvss_base: 8.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    kev_listed: true,
    kev_due_date: '2022-03-17',
    exploit_maturity: 'weaponized',
    published_at: '2017-03-16T00:00:00Z',
    product: 'Microsoft Windows SMB',
  },
  {
    cve_id: 'CVE-2022-22965',
    description:
      'Spring MVC and Spring WebFlux applications running on JDK 9+ may be vulnerable to remote code execution via data binding (Spring4Shell).',
    cvss_base: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    kev_listed: true,
    kev_due_date: '2022-04-25',
    exploit_maturity: 'weaponized',
    published_at: '2022-04-01T00:00:00Z',
    product: 'Apache Tomcat',
  },
  {
    cve_id: 'CVE-2023-4863',
    description:
      'Heap buffer overflow in libwebp allows a remote attacker to perform an out-of-bounds memory write via a crafted image.',
    cvss_base: 8.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
    kev_listed: true,
    kev_due_date: '2023-10-04',
    exploit_maturity: 'poc',
    published_at: '2023-09-12T00:00:00Z',
    product: 'nginx',
  },
  {
    cve_id: 'CVE-2020-1472',
    description:
      'An elevation of privilege vulnerability in the Netlogon Remote Protocol allows an unauthenticated attacker to compromise a domain controller (Zerologon).',
    cvss_base: 10.0,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    kev_listed: true,
    kev_due_date: '2021-08-09',
    exploit_maturity: 'weaponized',
    published_at: '2020-08-17T00:00:00Z',
    product: 'Microsoft Windows SMB',
  },
  {
    cve_id: 'CVE-2022-0778',
    description:
      'The BN_mod_sqrt() function in OpenSSL can loop forever for non-prime moduli, enabling denial of service via a crafted certificate.',
    cvss_base: 7.5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    kev_listed: false,
    kev_due_date: null,
    exploit_maturity: 'poc',
    published_at: '2022-03-15T00:00:00Z',
    product: 'OpenSSL',
  },
  {
    cve_id: 'CVE-2023-38408',
    description:
      'The PKCS#11 feature in ssh-agent has an insufficiently trustworthy search path, allowing remote code execution under certain conditions.',
    cvss_base: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    kev_listed: false,
    kev_due_date: null,
    exploit_maturity: 'poc',
    published_at: '2023-07-20T00:00:00Z',
    product: 'OpenSSH',
  },
  {
    cve_id: 'CVE-2021-23017',
    description:
      'A resolver off-by-one heap write in nginx may allow an attacker to corrupt memory and potentially execute code.',
    cvss_base: 7.7,
    cvss_vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:L',
    kev_listed: false,
    kev_due_date: null,
    exploit_maturity: 'poc',
    published_at: '2021-06-01T00:00:00Z',
    product: 'nginx',
  },
  {
    cve_id: 'CVE-2022-31160',
    description:
      'jQuery UI checkboxradio is vulnerable to cross-site scripting through the label element when untrusted input is used.',
    cvss_base: 6.1,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    kev_listed: false,
    kev_due_date: null,
    exploit_maturity: 'none',
    published_at: '2022-07-19T00:00:00Z',
    product: 'Apache httpd',
  },
  {
    cve_id: 'CVE-2023-25690',
    description:
      'HTTP request smuggling in Apache HTTP Server when mod_proxy is enabled with certain RewriteRule configurations.',
    cvss_base: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    kev_listed: false,
    kev_due_date: null,
    exploit_maturity: 'poc',
    published_at: '2023-03-07T00:00:00Z',
    product: 'Apache httpd',
  },
  {
    cve_id: 'CVE-2019-11043',
    description:
      'Under certain nginx + php-fpm configurations, a crafted URL can cause an underflow leading to remote code execution.',
    cvss_base: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    kev_listed: true,
    kev_due_date: '2022-05-03',
    exploit_maturity: 'weaponized',
    published_at: '2019-10-28T00:00:00Z',
    product: 'nginx',
  },
  {
    cve_id: 'CVE-2021-3711',
    description:
      'A buffer overflow in the OpenSSL SM2 decryption implementation can allow attacker-controlled data to overflow the output buffer.',
    cvss_base: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    kev_listed: false,
    kev_due_date: null,
    exploit_maturity: 'none',
    published_at: '2021-08-24T00:00:00Z',
    product: 'OpenSSL',
  },
  {
    cve_id: 'CVE-2018-15473',
    description:
      'OpenSSH is prone to a user enumeration vulnerability due to differing responses to malformed authentication requests.',
    cvss_base: 5.3,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    kev_listed: false,
    kev_due_date: null,
    exploit_maturity: 'poc',
    published_at: '2018-08-17T00:00:00Z',
    product: 'OpenSSH',
  },
  {
    cve_id: 'CVE-2022-42889',
    description:
      'Apache Commons Text performs variable interpolation that can result in arbitrary code execution when given untrusted input (Text4Shell).',
    cvss_base: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    kev_listed: true,
    kev_due_date: '2022-11-16',
    exploit_maturity: 'weaponized',
    published_at: '2022-10-13T00:00:00Z',
    product: 'Apache Tomcat',
  },
  {
    cve_id: 'CVE-2020-8558',
    description:
      'The Kubernetes kube-proxy component allows adjacent hosts to reach services bound to the node localhost interface.',
    cvss_base: 5.4,
    cvss_vector: 'CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
    kev_listed: false,
    kev_due_date: null,
    exploit_maturity: 'none',
    published_at: '2020-07-27T00:00:00Z',
    product: 'PostgreSQL',
  },
  {
    cve_id: 'CVE-2019-9193',
    description:
      'PostgreSQL COPY TO/FROM PROGRAM allows a user in the pg_read_server_files role to execute arbitrary code as the database superuser.',
    cvss_base: 8.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
    kev_listed: false,
    kev_due_date: null,
    exploit_maturity: 'poc',
    published_at: '2019-04-01T00:00:00Z',
    product: 'PostgreSQL',
  },
  {
    cve_id: 'CVE-2016-2183',
    description:
      'DES and Triple DES ciphers as used in TLS have a birthday bound of approximately four billion blocks, allowing plaintext recovery (SWEET32).',
    cvss_base: 3.7,
    cvss_vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',
    kev_listed: false,
    kev_due_date: null,
    exploit_maturity: 'none',
    published_at: '2016-09-01T00:00:00Z',
    product: 'OpenSSL',
  },
];

export function severityOf(entry: CatalogEntry): Severity {
  return severityForCvss(entry.cvss_base);
}

/** Observed services, used to give assets plausible open ports. */
export const SERVICE_TEMPLATES = [
  { port: 22, protocol: 'tcp', service: 'ssh', product: 'OpenSSH', version: '8.9p1' },
  { port: 80, protocol: 'tcp', service: 'http', product: 'nginx', version: '1.18.0' },
  { port: 443, protocol: 'tcp', service: 'https', product: 'nginx', version: '1.18.0' },
  { port: 443, protocol: 'tcp', service: 'https', product: 'Apache httpd', version: '2.4.52' },
  {
    port: 8080,
    protocol: 'tcp',
    service: 'http-proxy',
    product: 'Apache Tomcat',
    version: '9.0.56',
  },
  { port: 5432, protocol: 'tcp', service: 'postgresql', product: 'PostgreSQL', version: '14.5' },
  {
    port: 445,
    protocol: 'tcp',
    service: 'microsoft-ds',
    product: 'Microsoft Windows SMB',
    version: '',
  },
  {
    port: 3389,
    protocol: 'tcp',
    service: 'ms-wbt-server',
    product: 'Microsoft Terminal Services',
    version: '',
  },
  { port: 25, protocol: 'tcp', service: 'smtp', product: 'Postfix smtpd', version: '3.6.4' },
  { port: 6379, protocol: 'tcp', service: 'redis', product: 'Redis', version: '6.2.6' },
] as const;

export const OS_TEMPLATES = [
  { family: 'Linux', version: '5.15' },
  { family: 'Linux', version: '6.1' },
  { family: 'Windows', version: 'Server 2019' },
  { family: 'Windows', version: 'Server 2022' },
  { family: 'VMware ESXi', version: '7.0' },
  { family: 'Embedded', version: null },
] as const;
