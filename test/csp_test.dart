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

import 'package:csp/csp.dart';
import 'package:test/test.dart';

void main() {
  group('Csp', () {
    test('== / hashCode', () {
      final object = Csp(connectSrc: ['x'], fontSrc: ['y']);
      final clone = Csp(connectSrc: ['x'], fontSrc: ['y']);
      final other = Csp(connectSrc: ['x']);

      expect(object, clone);
      expect(object, isNot(other));

      expect(object.hashCode, clone.hashCode);
      expect(object.hashCode, isNot(other.hashCode));
    });

    test('Csp.kind', () {
      expect(
        Csp.kind.jsonTreeDecode('default-src *'),
        Csp(defaultSrc: ['*']),
      );
    });

    test('Csp(...)', () {
      final csp = Csp(
        connectSrc: ['connect-src-item'],
        defaultSrc: ['default-src-item'],
        fontSrc: ['font-src-item'],
        imgSrc: ['img-src-item'],
        manifestSrc: ['manifest-src-item'],
        mediaSrc: ['media-src-item'],
        scriptSrc: ['script-src-item'],
        styleSrc: ['style-src-item'],
        frameAncestors: ['frame-ancestors-item'],
        navigateTo: ['navigate-to-item'],
        reportUri: 'report-uri-value',
        reportTo: 'report-to-value',
        upgradeInsecureRequests: true,
      );
      expect(csp.directivesMap, {
        'connect-src': ['connect-src-item'],
        'default-src': ['default-src-item'],
        'font-src': ['font-src-item'],
        'img-src': ['img-src-item'],
        'manifest-src': ['manifest-src-item'],
        'media-src': ['media-src-item'],
        'script-src': ['script-src-item'],
        'style-src': ['style-src-item'],
        'frame-ancestors': ['frame-ancestors-item'],
        'navigate-to': ['navigate-to-item'],
        'report-uri': ['report-uri-value'],
        'report-to': ['report-to-value'],
        'upgrade-insecure-requests': [],
      });
    });

    test('Csp.fromDirectives(_)', () {
      final directives = [
        CspDirective('media-src', ['a']),
        CspDirective('media-src', ['b']),
        CspDirective('other'),
      ];
      final csp = Csp.fromDirectives(directives);
      expect(csp.toSourceString(), 'media-src a b; other');
    });

    group('Csp.fromMap(_)', () {
      test('optimizes duplicates', () {
        final csp = Csp.fromMap({
          'default-src': ['v0', 'v0'],
        });
        expect(csp.directivesMap['default-src'], ['v0']);
        expect(csp.toSourceString(), 'default-src v0');
      });
    });

    test('checkSource(...)', () {
      final csp = Csp.fromMap({
        'default-src': ['v0', 'v0'],
      });
      final type = 'some-type';
      final uri = Uri(host: 'example');
      final selfUri = Uri(host: 'selfhost');

      // Valid URL
      csp.checkSource(type: type, uri: Uri(host: 'v0'), selfUri: selfUri);

      // Invalid URL
      try {
        csp.checkSource(
          type: type,
          uri: uri,
          selfUri: selfUri,
        );
        fail('Should have thrown');
      } on CspViolationError catch (e) {
        expect(e.action, type);
        expect(e.uri, uri);
        expect(e.csp, same(csp));
      }
    });

    group('getAllowedSources(_)', () {
      test('throws ArgumentError if argument ends with "-src"', () {
        final csp = Csp(
          defaultSrc: [Csp.wildcard],
        );
        expect(() => csp.getAllowedSources(type: 'default-src'),
            throwsArgumentError);
        expect(
            () => csp.getAllowedSources(type: 'img-src'), throwsArgumentError);
      });

      test('when default is specified', () {
        final csp = Csp(
          defaultSrc: [Csp.wildcard],
          imgSrc: [Csp.none],
        );
        expect(csp.getAllowedSources(type: 'default'), [Csp.wildcard]);
        expect(csp.getAllowedSources(type: 'connect'), [Csp.wildcard]);
        expect(csp.getAllowedSources(type: 'img'), [Csp.none]);
      });

      test('when default is not specified', () {
        final csp = Csp();
        expect(csp.getAllowedSources(type: 'default'), []);
        expect(csp.getAllowedSources(type: 'img'), []);
      });
    });

    group('isValid(...)', () {
      test('self', () {
        final csp = Csp.fromMap({
          'default-src': ['v0', "'self'"],
        });
        final type = 'some-action';
        final uri = Uri(host: 'example');
        final selfUri = Uri(host: 'selfhost');

        // Valid URL
        csp.checkSource(type: type, uri: Uri(host: 'v0'), selfUri: selfUri);

        // Invalid URL
        try {
          csp.checkSource(
            type: type,
            uri: uri,
            selfUri: selfUri,
          );
          fail('Should have thrown');
        } on CspViolationError catch (e) {
          expect(e.action, type);
          expect(e.uri, uri);
          expect(e.csp, same(csp));
        }
      });
    });

    group('Csp.parse(_)', () {
      test('empty string', () {
        final source = '';
        final csp = Csp.parse(source);
        expect(csp.directivesMap, isEmpty);
        expect(csp.toSourceString(), source);
      });

      test('multiple directives', () {
        final source = 'directive0; x; directive1 arg0; directive2 arg0 arg1';
        final csp = Csp.parse(source);
        expect(csp.directivesMap, {
          'directive0': [],
          'x': [],
          'directive1': ['arg0'],
          'directive2': ['arg0', 'arg1'],
        });
        expect(csp.toSourceString(), source);
      });

      test('when contains duplicates', () {
        final source = "default-src v0 v0 'self' 'self'";
        final csp = Csp.parse(source);
        expect(csp.directivesMap['default-src'], ["'self'", 'v0']);
        expect(csp.toSourceString(), source);
      });

      test("when contains 'none'", () {
        final source = "default-src v0 'none' b";
        final csp = Csp.parse(source);
        expect(csp.directivesMap['default-src'], ["'none'"]);
        expect(csp.toSourceString(), source);
      });

      test("when contains '*'", () {
        final source = 'default-src a * b';
        final csp = Csp.parse(source);
        expect(csp.directivesMap['default-src'], ['*']);
        expect(csp.toSourceString(), source);
      });

      test("*, 'none'", () {
        final source = "default-src v0 * 'none' v1";
        final csp = Csp.parse(source);
        expect(csp.directivesMap['default-src'], ["'none'"]);
        expect(csp.toSourceString(), source);
      });

      test("'none', *", () {
        final source = "default-src a 'none' * b";
        final csp = Csp.parse(source);
        expect(csp.directivesMap['default-src'], ["'none'"]);
        expect(csp.toSourceString(), source);
      });
    });
  });

  group('CspDirective', () {
    test('== / hashCode', () {
      final object = CspDirective('name', ['arg0']);
      final clone = CspDirective('name', ['arg0']);
      final other0 = CspDirective('OTHER', ['arg0']);
      final other1 = CspDirective('name', ['OTHER']);

      expect(object, clone);
      expect(object, isNot(other0));
      expect(object, isNot(other1));

      expect(object.hashCode, clone.hashCode);
      expect(object.hashCode, isNot(other0.hashCode));
      expect(object.hashCode, isNot(other1.hashCode));
    });
  });
}
