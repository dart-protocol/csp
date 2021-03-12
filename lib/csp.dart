// Copyright 2021 Gohilla Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

library csp;

import 'package:collection/collection.dart';
import 'package:kind/kind.dart';

/// [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)
/// declaration.
///
/// The class is immutable.
class Csp {
  /// "script-src"
  static const String typeForScriptSrc = 'script-src';

  /// Kind for serialization ([package:kind](https://pub.dev/packages/kind)).
  static final Kind<Csp> kind = CompositePrimitiveKind<Csp, String>.simple(
    name: 'Csp',
    primitiveKind: const StringKind(),
    fromPrimitive: (s) => Csp.parse(s),
    toPrimitive: (t) => t.toSourceString(),
  );

  /// Keyword "'none'".
  static const String none = "'none'";

  /// Keyword "*".
  static const String wildcard = '*';

  /// Keyword "'self'".
  static const String self = "'self'";

  /// Keyword "'unsafe-hashes'".
  static const String unsafeHashes = "'unsafe-hashes'";

  /// Keyword "'unsafe-inline'".
  static const String unsafeInline = "'unsafe-inline'";

  /// Keyword "'unsafe-eval'".
  static const String unsafeEval = "'unsafe-eval'";

  /// CSP declaration 'default-src: *'.
  static final Csp allowAny = Csp.parse('default-src: *');

  /// CSP declaration 'default-src: 'self''.
  static final Csp allowSelf = Csp.parse("default-src: 'self'");

  /// CSP declaration 'default-src: 'none''.
  static final Csp allowNone = Csp.parse("default-src: 'none'");

  static const _directivesEquality =
      MapEquality<String, List<String>>(values: ListEquality<String>());

  static final Csp _emptyCsp = Csp._parsed('', const {});

  final Map<String, List<String>> directivesMap;

  /// List of directives sorted by name.
  late final List<CspDirective> directives = () {
    final list = directivesMap.entries
        .map(
          (entry) => CspDirective(entry.key, entry.value),
        )
        .toList();
    list.sort((a, b) => a.directiveName.compareTo(b.directiveName));
    return List<CspDirective>.unmodifiable(list);
  }();

  String? _source;

  factory Csp({
    List<String>? connectSrc,
    List<String>? defaultSrc,
    List<String>? fontSrc,
    List<String>? frameAncestors,
    List<String>? imgSrc,
    List<String>? manifestSrc,
    List<String>? mediaSrc,
    List<String>? scriptSrc,
    List<String>? styleSrc,
    List<String>? navigateTo,
    String? reportTo,
    String? reportUri,
    bool upgradeInsecureRequests = false,
  }) {
    final map = <String, List<String>>{};
    if (connectSrc != null) {
      map['connect-src'] = connectSrc;
    }
    if (defaultSrc != null) {
      map['default-src'] = defaultSrc;
    }
    if (fontSrc != null) {
      map['font-src'] = fontSrc;
    }
    if (imgSrc != null) {
      map['img-src'] = imgSrc;
    }
    if (manifestSrc != null) {
      map['manifest-src'] = manifestSrc;
    }
    if (mediaSrc != null) {
      map['media-src'] = mediaSrc;
    }
    if (scriptSrc != null) {
      map['script-src'] = scriptSrc;
    }
    if (styleSrc != null) {
      map['style-src'] = styleSrc;
    }

    if (frameAncestors != null) {
      map['frame-ancestors'] = frameAncestors;
    }
    if (navigateTo != null) {
      map['navigate-to'] = navigateTo;
    }
    if (reportTo != null) {
      map['report-to'] = [reportTo];
    }
    if (reportUri != null) {
      map['report-uri'] = [reportUri];
    }
    if (upgradeInsecureRequests) {
      map['upgrade-insecure-requests'] = [];
    }
    if (upgradeInsecureRequests) {
      map['upgrade-insecure-requests'] = [];
    }
    return Csp.fromMap(map);
  }

  /// Constructs CSP declaration from [CspDirective] instances.
  factory Csp.fromDirectives(Iterable<CspDirective> directives) {
    return Csp.merge(directives.map((e) {
      return Csp.fromMap({e.directiveName: e.arguments});
    }));
  }

  /// Constructs CSP declaration from the map.
  ///
  /// Throws [ArgumentError] if the argument contains invalid strings.
  Csp.fromMap(Map<String, List<String>> directivesMap)
      : directivesMap = _immutableOptimizeddirectivesMap(directivesMap),
        _source = null {
    for (var argumentList in directivesMap.values) {
      for (var argument in argumentList) {
        // Look for illegal/unusual characters
        if (argument.codeUnits.any((e) => e <= 32 || e == 127) ||
            argument.contains(';')) {
          throw ArgumentError('Unsupported CSP pattern: `$argument`');
        }
      }
    }
  }

  /// Merges CSP declarations.
  factory Csp.merge(Iterable<Csp> csps) {
    final directivesMap = <String, List<String>>{};
    for (var csp in csps) {
      for (var entry in csp.directivesMap.entries) {
        if (entry.key.endsWith('-src')) {
          final argument = directivesMap.putIfAbsent(entry.key, () => []);
          for (var directive in entry.value) {
            if (!argument.contains(directive)) {
              argument.add(directive);
            }
          }
          argument.addAll(entry.value);
        } else {
          directivesMap[entry.key] = entry.value;
        }
      }
    }
    return Csp.fromMap(directivesMap);
  }

  Csp._parsed(this._source, Map<String, List<String>> directivesMap)
      : directivesMap = _immutableOptimizeddirectivesMap(directivesMap);

  @override
  int get hashCode => _directivesEquality.hash(directivesMap);

  @override
  bool operator ==(other) =>
      other is Csp &&
      _directivesEquality.equals(directivesMap, other.directivesMap);

  /// Throws [CspViolationError] if the action is not allowed.
  void checkSource({
    required String type,
    required Uri uri,
    required Uri? selfUri,
  }) {
    if (!isAllowedSource(type: type, uri: uri, selfUri: selfUri)) {
      throw CspViolationError(
        action: type,
        uri: uri,
        csp: this,
      );
    }
  }

  /// Returns directives for the type ('connect', 'img', etc.).
  ///
  /// # Example
  /// ```
  /// final allowesSources = csp.getAllowedSources(type: 'img');
  /// ```
  List<String> getAllowedSources({required String type}) {
    // Prevent developers from using the API incorrectly.
    if (type.endsWith('-src')) {
      throw ArgumentError.value(type, 'type', 'Must not end with "-src"');
    }
    return directivesMap['$type-src'] ??
        directivesMap['default-src'] ??
        const <String>[];
  }

  /// Evaluates whether the action is allowed.
  bool isAllowedSource({
    required String type,
    required Uri uri,
    required Uri? selfUri,
  }) {
    final directives = getAllowedSources(type: type);
    if (directives.contains(none)) {
      return false;
    }
    if (directives.contains(wildcard)) {
      return true;
    }
    if (directives.contains(self) && selfUri != null) {
      if (selfUri.host == uri.host) {
        return true;
      }
    }
    for (var directive in directives) {
      if (directive.contains('://')) {
        final parseddirective = Uri.parse(directive);
        if (parseddirective.scheme == uri.scheme &&
            parseddirective.host == uri.host) {
          return true;
        }
      } else {
        if (directive == uri.host) {
          return true;
        }
      }
    }
    return false;
  }

  /// Returns the CSP string.
  ///
  /// If the instance was constructed by [parse] or [tryParse], the method
  /// returns the original parsed string.
  ///
  /// Otherwise the method constructs a new string.
  String toSourceString() {
    var source = _source;
    if (source == null) {
      final directiveNames = directivesMap.keys.toList(growable: false)..sort();
      final sb = StringBuffer();
      var semicolon = false;
      final sortedDirectiveNames = directiveNames.toList(growable: false)
        ..sort();
      for (var directiveName in sortedDirectiveNames) {
        if (semicolon) {
          sb.write('; ');
        }
        semicolon = true;
        sb.write(directiveName);
        final arguments = directivesMap[directiveName]!;
        for (var argument in arguments) {
          sb.write(' ');
          sb.write(argument);
        }
      }
      source = sb.toString();
      _source = source;
    }
    return source;
  }

  @override
  String toString() {
    return 'Csp.parse("${toSourceString()}")';
  }

  static Csp parse(String input) {
    final result = tryParse(input);
    if (result == null) {
      throw FormatException('Invalid CSP policy: "$input"');
    }
    return result;
  }

  static Csp? tryParse(String input) {
    input = input.trim();
    if (input.isEmpty) {
      return _emptyCsp;
    }
    final directivesMap = <String, List<String>>{};
    for (var directive in input.split('; ')) {
      final items = directive.split(' ');
      directivesMap[items.first] = List<String>.unmodifiable(items.skip(1));
    }
    _immutableOptimizeddirectivesMap(directivesMap);
    return Csp._parsed(input, directivesMap);
  }

  static Map<String, List<String>> _immutableOptimizeddirectivesMap(
      Map<String, List<String>> directivesMap) {
    final newMap = <String, List<String>>{};
    for (var entry in directivesMap.entries) {
      final directiveName = entry.key;
      var arguments = entry.value;
      if (directiveName.endsWith('-src')) {
        if (arguments.contains(none)) {
          arguments = const [none];
        } else if (arguments.contains(wildcard)) {
          arguments = const [wildcard];
        } else {
          // Construct sorted immutable list.
          arguments = List<String>.unmodifiable(
            arguments.toSet().toList()..sort(),
          );
        }
      } else {
        arguments = List<String>.unmodifiable(arguments);
      }
      newMap[entry.key] = arguments;
    }
    return Map<String, List<String>>.unmodifiable(
      newMap,
    );
  }
}

/// [Csp] directive.
class CspDirective {
  final String directiveName;
  final List<String> arguments;

  const CspDirective(this.directiveName, [this.arguments = const []]);

  @override
  int get hashCode =>
      directiveName.hashCode ^ const ListEquality<String>().hash(arguments);

  @override
  bool operator ==(other) =>
      other is CspDirective &&
      directiveName == other.directiveName &&
      const ListEquality<String>().equals(arguments, other.arguments);

  @override
  String toString() {
    if (arguments.isEmpty) {
      return 'CspDirective("$directiveName")';
    }
    return 'CspDirective("$directiveName", ["${arguments.join('", "')}"])';
  }
}

/// Error thrown when [Csp] is violated.
class CspViolationError extends Error {
  final String action;
  final Uri uri;
  final Csp csp;

  CspViolationError({
    required this.action,
    required this.uri,
    required this.csp,
  });

  @override
  String toString() {
    return 'CspViolationError(action: "$action", uri: "$uri", csp: $csp)';
  }
}
