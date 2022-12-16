import 'dart:typed_data';

import 'package:bip47/src/util.dart';
import 'package:convert/convert.dart';
import 'package:pointycastle/ecc/api.dart';

class SecretPoint {
  ECPrivateKey? _privKey;
  ECPublicKey? _pubKey;

  final parameters = ECDomainParameters("secp256k1");
  SecretPoint(Uint8List priv, Uint8List pub) {
    _privKey = _loadPrivateKey(priv);
    _pubKey = _loadPublicKey(pub);
  }

  ECPrivateKey get privKey => _privKey!;
  ECPublicKey get pubKey => _pubKey!;

  set privKey(ECPrivateKey value) {
    _privKey = value;
  }

  set pubKey(ECPublicKey value) {
    _pubKey = value;
  }

  Uint8List ecdhSecret() {
    final result =
        (ECDHBasicAgreement()..init(privKey)).calculateAgreement(pubKey);
    return Uint8List.fromList(hex.decode(_toHex(result)));
  }

  // bool _equals(SecretKey other) {
  //   return
  // }

  ECPublicKey _loadPublicKey(Uint8List data) {
    final ecPoint = parameters.curve.decodePoint(data);
    return ECPublicKey(ecPoint, parameters);
  }

  ECPrivateKey _loadPrivateKey(Uint8List data) {
    final num = Util.bytesToInt(data);
    return ECPrivateKey(num, parameters);
  }

  String _toHex(BigInt num) {
    String hex = num.toRadixString(16);
    if (hex.length % 2 == 0) {
      return hex;
    } else {
      return "0$hex";
    }
  }
}
