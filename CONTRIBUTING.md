# Contributing to SwitchPortQuery

We welcome contributions!

1. Fork the repo
2. Create a branch (`git checkout -b feature/your-feature`)
3. Make your changes with tests and doc updates
4. Run linters and tests:
   ```bash
   pip install flake8 black isort pytest
   flake8 .
   black --check .
   isort --check-only .
   pytest
   ```
5. Commit (`git commit -m "feat: description"`) and push
6. Open a pull request against `main`