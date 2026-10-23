# 🤝 Contributing to SBOMGuard

Thank you for your interest in contributing to **SBOMGuard**! We welcome contributions from developers, security researchers, and students.

---

## 🛠️ Development Setup

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/Sumathikn/SBOM.git
   cd SBOM/SBOMGuard
   ```

2. **Set up a Python 3.12 virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt -e .
   ```

3. **Verify the test suite:**
   ```bash
   python3 -m pytest tests/ -v
   ```

---

## 📐 Code Standards & Architecture Guidelines

- **Asynchronous I/O:** All network calls, database queries, and filesystem operations must be non-blocking (`async`/`await`).
- **Resilience:** Any outbound HTTP requests to external threat intelligence sources or package registries must be wrapped in a `CircuitBreaker`.
- **Security:**
  - Never disable security headers in middleware.
  - All database queries must use SQLAlchemy 2.0 async parameterization (prevent SQLi).
  - All uploaded files must respect the 10 MB payload limiter.
- **Testing:** New parsers, engines, or endpoints must include corresponding pytest unit and integration tests.

---

## 🚀 Submitting a Pull Request (PR)

1. Create a feature branch: `git checkout -b feature/your-feature-name`.
2. Commit your changes: `git commit -m "feat: describe your change"`.
3. Push to your fork: `git push origin feature/your-feature-name`.
4. Open a Pull Request targeting `main`. Ensure all CI checks (pytest, SARIF security scan, and gatekeeper) pass.
