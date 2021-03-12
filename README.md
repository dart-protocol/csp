[![Pub Package](https://img.shields.io/pub/v/csp.svg)](https://pub.dartlang.org/packages/csp)
[![Github Actions CI](https://github.com/dint-dev/csp/workflows/Dart%20CI/badge.svg)](https://github.com/dint-dev/csp/actions?query=workflow%3A%22Dart+CI%22)

# Overview

A package for reading and writing [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)
strings.

Licensed under the [Apache License 2.0](LICENSE).

## Links
  * [Pub package](https://pub.dev/packages/csp)
  * [Issue tracker](https://github.com/dint-dev/csp/issues)
  * [Create a pull request](https://github.com/dint-dev/csp/pull/new/master)

# Getting started
## 1.Add dependency
In _pubspec.yaml_:
```yaml
dependencies:
  csp: ^0.1.1
```

## 2.Use
```dart
import 'package:csp/csp.dart';

Future<void> main() async {
  // Construct CSP
  var csp = Csp(
    defaultSrc: [Csp.self, 'google.com'],
  );

  // Parse CSP
  final parsedCsp = Csp.parse('default-src: microsoft.com');

  // Merge CSPs
  final mergedCsp = Csp.merge([csp, parsedCsp]);

  // Print CSP
  print(mergedCsp.toSourceString());

  // Throw CspError if the action is invalid
  csp.checkSource(
    type: 'connect',
    uri: Uri.parse('google.com'),
    selfUri: null,
  );
}
```