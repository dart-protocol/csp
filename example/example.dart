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