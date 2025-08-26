# Changelog

All notable changes to the paseto4j project will be documented in this file.

## 2024.3 (Unreleased)

### ✨ New Features

- 🔐 Added support for lazysodium, replacing the deprecated Tuweni library for XChaCha20Poly1305 encryption
- 🧩 Introduced `Hex` class for better handling of binary data with proper equals, hashCode, and toString behavior
- 🛡️ Improved key handling with typed key representations
- 📦 Enhanced support for Bouncy Castle cryptographic operations

### 🐛 Bug Fixes

- 🔧 Fixed issue with SHAKE digest handling in crypto operations
- 🔍 Corrected RSA key handling for proper signing operations
- 🧪 Resolved issues with key length validation for secure operations
- 🚫 Fixed license header issues with multi-module project structure

### 🔧 Technical Updates

- 📈 Upgraded to Bouncy Castle 1.80
- 🏗️ Moved to Java 17 as minimum supported version
- 🧹 Added Google Error Prone for enhanced static code analysis
- 🧪 Improved test coverage with parameterized tests
- 📝 Added Spotless formatting integration in the compile phase
- 🔄 Updated Jackson dependencies to version 2.18.3
- 🛠️ Enhanced build process with better Maven plugin configuration
- 📊 Added JaCoCo for code coverage reporting

### 🔀 Breaking Changes

- ⚠️ Changed key representations to use byte arrays instead of various key types
- ⚠️ Removed support for deprecated cryptographic functions
- ⚠️ Refactored API to provide clearer type safety for different key types

## Previous Releases

For information about previous releases, please see the [GitHub release page](https://github.com/nbaars/paseto4j/releases).
