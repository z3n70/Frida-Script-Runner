# Contributing to Frida Script Runner

First off, thank you for considering contributing to Frida Script Runner! It's people like you that make this project great.

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the issue list as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

- **Use a clear and descriptive title**
- **Describe the exact steps to reproduce the problem**
- **Provide specific examples to demonstrate the steps**
- **Describe the behavior you observed after following the steps**
- **Explain which behavior you expected to see instead and why**
- **Include screenshots and animated GIFs if applicable**
- **Include details about your configuration and environment:**
  - OS version
  - Python version
  - Frida version
  - Device type (Android/iOS) and version

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

- **Use a clear and descriptive title**
- **Provide a step-by-step description of the suggested enhancement**
- **Provide specific examples to demonstrate the steps**
- **Describe the current behavior and explain which behavior you expected to see instead**
- **Explain why this enhancement would be useful**

### Pull Requests

1. **Fork the repository** and create your branch from `develop` (or `main` if `develop` doesn't exist)
2. **Make your changes** following the coding standards
3. **Test thoroughly** on both Android and iOS devices if applicable
4. **Update documentation** if you've changed functionality
5. **Commit your changes** using clear commit messages
6. **Push to your fork** and submit a pull request

#### Pull Request Guidelines

- Fill out the pull request template completely
- Do not include issue numbers in the PR title
- Include screenshots and animated GIFs in your pull request whenever possible
- Follow the Python style guide (PEP 8)
- Include tests if you've added new functionality
- Make sure all tests pass on your local machine
- Update the README.md with details of changes if applicable

## Development Setup

1. Clone your fork of the repository:
   ```bash
   git clone https://github.com/z3n70/Frida-Script-Runner.git
   cd Frida-Script-Runner
   ```

2. Create a virtual environment:
   ```bash
   python3.11 -m venv venv
   source venv/bin/activate  
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Make your changes and test them

5. Run any existing tests (if available)

## Coding Standards

- Follow PEP 8 style guide for Python code
- Use meaningful variable and function names
- Add comments for complex logic
- Keep functions focused and single-purpose
- Write docstrings for functions and classes

## Commit Message Guidelines

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests liberally after the first line

## Testing

- Test your changes on both Android and iOS devices when applicable
- Test edge cases and error conditions
- Ensure backward compatibility when possible

## Questions?

Feel free to reach out to the maintainer:
- Twitter: [@zenalarifin_](https://x.com/zenalarifin_)
- GitHub Issues: For bug reports and feature requests

Thank you for contributing! 🎉
