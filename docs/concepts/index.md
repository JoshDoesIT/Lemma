# Concepts

Understand the architectural decisions and data structures behind Lemma.

## The OSCAL Baseline
All policies, control structures, implemented evidence, and catalogs in Lemma are natively bridged back to [NIST OSCAL (Open Security Controls Assessment Language)](https://pages.nist.gov/OSCAL/). This guarantees data portability and prevents vendor lock-in.

## Harmonization & The CCF
Instead of addressing disjointed frameworks (SOC2, ISO 27001, HIPAA) independently, Lemma leverages a Common Control Framework (CCF) architecture. You map your internal policy to our CCF layer via the `lemma harmonize` engine, which then multiplexes that verified compliance state out to every overlapping framework requirement. 
