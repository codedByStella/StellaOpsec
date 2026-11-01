# Project Scope

StellaOpsec is a personal collection of experimental PowerShell scripts. I use it to explore security-related concepts and to think more carefully about the systems and automation I build.

The scripts are intended for one limited operational purpose: when a business owner specifically requests it, I may use them alongside StellaAudits to gather additional information and bring observations to that owner's attention.

They are not released for public use, redistribution, or independent operation by third parties.

## What is in the repository

Depending on the script, it may collect selected information about:

- Windows hosts, accounts, services, processes, event logs, and network configuration.
- Active Directory and Group Policy.
- Network services, DNS behavior, TLS connections, and HTTP responses.
- Azure and Google Cloud configuration.
- Structured data used to create CSV, Excel, or HTML reports.

The individual project notes describe the scripts, dependencies, and known limitations.

## What the output means

The scripts collect selected information. They can miss relevant details, return incomplete data, or produce observations that need context. A result is not proof that a system is secure, insecure, compromised, or exploitable. An absence of output is not proof that a problem is absent.

I do not provide security remediation or certify the security of an environment. If the information raises enough questions to warrant further investigation, the business owner decides whether to engage a qualified professional for a proper assessment or remediation.

My role is limited to collecting information and communicating observations. I am not acting as a security authority.

## About the project

I am a hobbyist with an interest in security, not a credentialed security professional. StellaOpsec is an engineering and learning project. It demonstrates an interest in security-conscious development, not professional OPSEC expertise or qualifications to conduct security assessments.
