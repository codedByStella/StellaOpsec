# StellaOpsec

StellaOpsec is a personal, experimental collection of PowerShell scripts developed while exploring security-conscious automation and configuration awareness.

This project demonstrates an interest in security and an awareness of how security considerations affect software development. It is not evidence of professional security expertise, OPSEC competency, or qualifications to conduct security assessments.

The scripts are personal development artifacts. They are not released for public use, redistribution, or independent operation. Their only intended operational use is alongside StellaAudits, when a business owner specifically requests limited information gathering.

## Intended role

StellaOpsec has one intended operational purpose: to assist StellaAudits by collecting limited information that may help bring potentially relevant conditions to a business owner's attention.

It is not a security audit, penetration test, vulnerability assessment, compliance review, or certification. I do not provide security remediation, determine whether an environment is secure, or claim that the scripts can identify every relevant issue.

If the information collected raises enough questions to warrant further investigation, the business owner can decide whether to engage a qualified professional for a proper assessment or remediation.

My role is limited to gathering information and communicating observations. I am the messenger, not the security authority.

## Repository contents

The repository is organized by the areas explored in the scripts:

| Directory | Contents |
|---|---|
| [windows/](windows/) | Windows host, credential-protection, event-log, and environment inventory scripts |
| [windows/active-directory/](windows/active-directory/) | Active Directory and Group Policy information gathering |
| [network/](network/) | Network discovery and limited DNS, TLS, and web configuration checks |
| [cloud/azure/](cloud/azure/) | Azure configuration information gathering through Azure CLI |
| [cloud/gcp/](cloud/gcp/) | Google Cloud configuration information gathering through gcloud |
| [automation/](automation/) | Report generation and export helpers |
| [docs/](docs/) | Project scope and disclosure notes |

The directory and module documentation records the original development intent, dependencies, and known limitations. It is included as project documentation, not as instructions for third-party operation.

## Limitations

I am a hobbyist with an interest in security, not a credentialed security professional. My knowledge is limited, and these scripts reflect that.

The scripts may misinterpret configurations, overlook relevant conditions, produce false positives, or fail to identify genuine issues. Their output must not be treated as proof of security, proof of compromise, or a substitute for professional evaluation.

Collection may also be incomplete because of permissions, unavailable commands, API behavior, provider differences, or the state of the environment being examined. Results are limited observations from the time they were collected.

The scripts are not offered as a service and are not authorized for independent use by third parties. No guarantee is made regarding their accuracy, completeness, suitability, or fitness for any purpose.

## Why this project exists

Security awareness matters even when security is not someone's primary profession.

I build automation and applications. Exploring security-related concepts gives me another way to think about the systems I build, the information they handle, and the limitations of my own implementations.

I build automation. I have an interest in security. I know enough to recognize that I don't know enough to certify the answers.
