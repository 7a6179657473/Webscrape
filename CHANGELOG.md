# Changelog

All notable changes to the Webscrape project.

## [Unreleased]

### Added
- **`--allow-private` flag**: Opt-in mode to scrape authorized private/internal
  targets (lab, CTF, or internal hosts on `10.x`/`172.16.x`/`192.168.x` ranges).
  The SSRF guard in `validate_url()` remains **on by default**; the flag only
  relaxes the private/loopback/link-local IP, internal-hostname/TLD, and
  DNS-resolves-to-private checks. Scheme (`http`/`https` only), host, and
  URL-length validation stay enforced. Threaded into both the single-URL and
  spider validation paths.
  - Usage: `python webscrape.py http://10.10.10.5/ --allow-private`

### Documentation
- README.md: documented `--allow-private` in the Command Line Options table and
  added a "Scanning Internal / Lab Targets" usage section.
- SECURITY_FEATURES.md: documented the default SSRF protection and the
  `--allow-private` opt-out.

## [2.0.0] - 2025-09-15

### Major Updates & Refactoring

#### 📝 Documentation Overhaul
- **README.md**: Complete rewrite with comprehensive documentation
  - Added detailed feature descriptions for single-page and spider crawling
  - Included installation instructions with prerequisites
  - Added extensive usage examples with command-line options
  - Created project structure visualization
  - Added security considerations and contributing guidelines
  - Professional formatting with emojis and clear sections

- **WARP.md**: Updated development guidance
  - Refreshed dependency version information
  - Added missing Python modules to documentation
  - Updated installation instructions to include requirements.txt
  - Ensured consistency with actual codebase functionality

#### 🛠️ Project Structure Improvements
- **requirements.txt**: Created comprehensive dependency file
  - Lists main dependencies (requests, beautifulsoup4)
  - Documents all standard library modules used
  - Version requirements for external packages

- **.gitignore**: Added comprehensive ignore patterns
  - Python-specific patterns for __pycache__, .pyc files
  - Development environment files (.venv, .env)
  - IDE files (.vscode, .idea)
  - Generated output files (*.html, logs)
  - OS-specific files (Thumbs.db, .DS_Store)

- **pyproject.toml**: Modern Python project configuration
  - Project metadata and author information
  - Dependency specifications
  - Development dependencies for testing and linting
  - Tool configurations for black, isort, mypy, pytest
  - Entry point configuration for CLI usage

#### 💻 Code Quality Improvements
- **webscrape.py**: Enhanced documentation and maintainability
  - Added comprehensive module-level docstring with version info
  - Improved function docstrings with detailed Args/Returns
  - Added constants for configuration values (timeouts, limits, patterns)
  - Refactored code to use defined constants instead of magic numbers
  - Added type hints to main function
  - Better organization with __version__, __author__ metadata

#### 🔧 Constants & Configuration
- Added centralized constants for better maintainability:
  - `DEFAULT_TIMEOUT`: Request timeout (10 seconds)
  - `MAX_URL_LENGTH`: Maximum URL length (2048 characters)
  - `MAX_FILENAME_LENGTH`: Maximum filename length (100 characters)
  - `DEFAULT_SPIDER_DEPTH`: Default crawling depth (2 levels)
  - `DEFAULT_SPIDER_DELAY`: Default delay between requests (1.0 seconds)
  - `DEFAULT_USER_AGENT`: Standardized browser user-agent string
  - `EMAIL_PATTERN`: RFC 5322 compliant email regex
  - `SKIP_EXTENSIONS`: File extensions to skip during crawling

#### 🎯 Enhanced Features
- Maintained all existing functionality:
  - Single-page web scraping with link and email extraction
  - Advanced spider crawling with depth control
  - Interactive HTML report generation
  - Security features and input validation
  - Command-line interface with comprehensive options

#### 📊 Project Status
- Version bumped to 2.0.0 to reflect major documentation and structure improvements
- All files updated to maintain consistency and relevancy
- Project now follows modern Python packaging standards
- Enhanced maintainability through better documentation and constants
- Ready for potential future enhancements and contributions

### Files Modified
- `README.md` - Complete rewrite with comprehensive documentation
- `WARP.md` - Updated dependencies and installation instructions  
- `webscrape.py` - Enhanced documentation, constants, and type hints

### Files Added
- `requirements.txt` - Python dependencies specification
- `.gitignore` - Comprehensive ignore patterns
- `pyproject.toml` - Modern Python project configuration
- `CHANGELOG.md` - This changelog file

### Breaking Changes
None. All existing functionality and command-line interfaces remain unchanged.

### Migration Guide
No migration needed. Existing usage patterns continue to work as before.

---

*This update focuses on maintainability, documentation, and project structure while preserving all existing functionality.*
