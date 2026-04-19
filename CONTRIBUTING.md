# Contributing to Lemma

Thank you for your interest in contributing to Lemma! We are building an open-source, AI-native GRC platform that treats compliance as a rigorous, provable engineering discipline. 

We welcome contributions from GRC engineers, security practitioners, and developers.

## 🏗️ Development Workflow

Lemma follows a strict **Test-Driven Development (TDD)** and **Spec-Driven Development (SDD)** approach.

### The Golden Rule: No Code Without a Test
If you are writing production code, there must be a failing test for it first. If code is written before a test, it will be rejected during review.

### Development Environment Setup
*(Note: Tech stack specifics will be updated here in Phase 1 once the project is initialized.)*

1. Fork the repository
2. Clone your fork locally
3. Install dependencies 
4. Verify your environment by running the test suite

## 🌿 Branch Naming Conventions

We use conventional branch names to organize work:

- `feat/your-feature-name` — For new features or significant additions.
- `fix/issue-description` — For bug fixes.
- `docs/what-you-documented` — For documentation-only changes.
- `ref/what-you-refactored` — For code refactoring without behavior changes.
- `chore/maintenance-task` — For tooling, dependency updates, or repository maintenance.

## 📝 Commit Message Conventions

We adhere strictly to [Conventional Commits](https://www.conventionalcommits.org/). Your PR title and commits must follow this format:

```text
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Common Types:**
- `feat:` A new feature
- `fix:` A bug fix
- `docs:` Documentation only changes
- `style:` Changes that do not affect the meaning of the code (white-space, formatting, etc)
- `refactor:` A code change that neither fixes a bug nor adds a feature
- `perf:` A code change that improves performance
- `test:` Adding missing tests or correcting existing tests
- `chore:` Changes to the build process or auxiliary tools and libraries

**Example:**
`feat(engine): add support for parsing OSCAL profiles`

*If your PR resolves an open issue, please include `Fixes #<issue-number>` in the commit body or PR description.*

## ✅ Pre-Submission Checklist

Before submitting your pull request, ensure you have completed the following:

- [ ] Rebased on the latest `main` branch
- [ ] Run the linter (`npm run lint` or equivalent) with no errors
- [ ] Formatted the code (`npm run format` or equivalent)
- [ ] Run the full test suite (`npm run test` or equivalent) and ensure all tests pass
- [ ] Performed a self-review of your changes
- [ ] Updated any relevant documentation (README, API docs, architecture diagrams)
- [ ] Ensure any new AI logic is highly transparent and logs its trace

## 🤝 Getting Help

If you have questions or need guidance on a feature, please start a discussion in [GitHub Discussions](https://github.com/JoshDoesIT/Lemma/discussions) or comment on the relevant issue.

**First time?** Look for issues labeled [`good-first-issue`](https://github.com/JoshDoesIT/Lemma/labels/status%3A%20good-first-issue).

---
*By contributing to Lemma, you agree that your contributions will be licensed under its Apache 2.0 License.*
