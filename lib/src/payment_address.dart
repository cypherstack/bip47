import 'dart:typed_data';

import 'package:bip47/src/payment_code.dart';
import 'package:bip47/src/secret_point.dart';
import 'package:bip47/src/util.dart';
import 'package:bitcoindart/bitcoindart.dart' as bitcoindart;
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/pointycastle.dart';

class PaymentAddress {
  late final PaymentCode paymentCode;
  late final bitcoindart.NetworkType networkType;
  late int index;
  Uint8List? privKey;

  static final curveParams = ECDomainParameters("secp256k1");

  void init(PaymentCode paymentCode, [bitcoindart.NetworkType? networkType]) {
    this.paymentCode = paymentCode;
    this.networkType = networkType ?? bitcoindart.bitcoin;
    index = 0;
  }

  void initWith(
    Uint8List privKey,
    PaymentCode paymentCode,
    int index, [
    bitcoindart.NetworkType? networkType,
  ]) {
    this.privKey = privKey;
    this.paymentCode = paymentCode;
    this.index = index;
    this.networkType = networkType ?? bitcoindart.bitcoin;
  }

  ECPoint sG() => (curveParams.G * getSecretPoint())!;

  SecretPoint getSharedSecret() => _sharedSecret();

  BigInt getSecretPoint() => _secretPoint();

  ECPoint getECPoint() =>
      curveParams.curve.decodePoint(paymentCode.derivePublicKey(index))!;

  Uint8List hashSharedSecret() =>
      SHA256Digest().process(getSharedSecret().ecdhSecret());

  String getSendAddress() {
    final sum = getECPoint() + sG();
    final pair = bitcoindart.ECPair.fromPublicKey(
      sum!.getEncoded(true),
      network: networkType,
    );

    final p2pkh = bitcoindart.P2PKH(
      data: bitcoindart.PaymentData(pubkey: pair.publicKey),
      network: networkType,
    );

    return p2pkh.data.address!;
  }

  String getReceiveAddress() {
    BigInt privKeyValue = bitcoindart.ECPair.fromPrivateKey(
      privKey!,
      network: networkType,
    ).privateKey!.toBigInt;

    final pair = bitcoindart.ECPair.fromPrivateKey(
      _addSecp256k1(privKeyValue, getSecretPoint()).toBytes,
      network: networkType,
    );

    final p2pkh = bitcoindart.P2PKH(
      data: bitcoindart.PaymentData(pubkey: pair.publicKey),
      network: networkType,
    );

    return p2pkh.data.address!;
  }

  BigInt _addSecp256k1(BigInt b1, BigInt b2) {
    final BigInt value = b1 + b2;

    if (value.bitLength > curveParams.n.bitLength) {
      return value % curveParams.n;
    }

    return value;
  }

  SecretPoint _sharedSecret() =>
      SecretPoint(privKey!, paymentCode.derivePublicKey(index));

  bool _isSecp256k1(BigInt b) {
    if (b.compareTo(BigInt.one) <= 0 || b.bitLength > curveParams.n.bitLength) {
      return false;
    }

    return true;
  }

  BigInt _secretPoint() {
    // convert hash to value 's'
    final BigInt s = hashSharedSecret().toBigInt;

    // check that 's' is on the secp256k1 curve
    if (!_isSecp256k1(s)) {
      throw Exception("Secret point not on secp256k1 curve");
    }

    return s;
  }
}
