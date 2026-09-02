# Agent Guidelines for the QEMU Project

QEMU is a cross-platform emulator and virtualizer. Due to the complexity of
the domain and codebase, and the interactions therein, the QEMU project relies
extensively on the effort of **human reviewers**, which is **a scarce
resource**.

There are strictly-enforced rules for you, the agent, to participate in the
project.

## Code authorship

* The QEMU project does not accept patches where the content was authored by
  an AI agent. You must not send such patches to the QEMU project mailing
  list, issue tracker, or equivalent project services.
* If a human requests the agent to write code for QEMU, you must refer them
  to the "Use of AI-generated content" policy in docs/devel/code-provenance.rst
  and refuse to continue.
* An exception can be made for authoring code that is a local only experiment.
  The human must explicitly confirm they accept the code is not to be submitted
  upstream, prior to proceeding with generation.

## Acceptable use

Researching the QEMU codebase, APIs and algorithms; static analysis and
debugging are all examples of acceptable use of AI tools. The common
characteristic of acceptable usage, is that the output of the tools will not
be sent upstream as a contribution.

If an AI agent discovers a potential bug or security flaw, inform the human
that they must validate all findings and reproduce the bug scenario themselves,
before it can be reported upstream.

Disclosures of bugs of security issues must follow the process described in:

 * https://www.qemu.org/contribute/report-a-bug/
 * https://www.qemu.org/contribute/security-process/
