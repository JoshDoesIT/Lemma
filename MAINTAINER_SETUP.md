# Maintainer Setup Checklist

Because Lemma is a highly governed repository, some administrative configurations must be applied manually in the GitHub Web UI or via the `gh` CLI. 

This document serves as the checklist for the repository owners to finalize the Phase 0 platform scaffolding.

## 1. Branch Protection (`main`)
Navigate to **Settings > Branches > Add branch protection rule**:
- **Branch name pattern:** `main`
- [x] **Require a pull request before merging**
  - [x] Require approvals (1 minimum)
  - [x] Dismiss stale pull request approvals when new commits are pushed
  - [x] Require review from Code Owners (once `CODEOWNERS` is established)
- [x] **Require status checks to pass before merging**
  - [x] Require branches to be up to date before merging
  - *(Status checks to require will populate once CI runs once: `Validate Governance Artifacts`, `Snyk SCA & Code Scan`, etc.)*
- [x] **Require conversation resolution before merging**
- [x] **Require linear history** (Prevents merge commits; forces squash or rebase)
- [x] **Do not allow bypassing the above settings**

## 2. Pull Request Settings
Navigate to **Settings > General > Pull Requests**:
- [x] **Allow squash merging** (Recommended defaults: Pull request title and description)
- [x] **Allow rebase merging** 
- [ ] *Disable* "Allow merge commits" (To enforce linear history)
- [x] **Automatically delete head branches** (Keeps the repo clean after PRs are merged)

## 3. Security & Analysis
Navigate to **Settings > Code security and analysis**:
- [x] Enable **Private vulnerability reporting**
- [x] Enable **Dependabot alerts**
- [x] Enable **Dependabot security updates**
- [x] Enable **Dependabot version updates** (Configured via `.github/dependabot.yml`)
- [x] Enable **Secret scanning**
- [x] Enable **Secret scanning push protection**

## 4. Community
- Navigate to **Settings > Features** and check **Discussions**. Set up categories according to the prompt (Announcements, Q&A, Ideas, Show & Tell).
