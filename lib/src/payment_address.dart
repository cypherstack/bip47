import 'dart:typed_data';

import 'package:bip32/bip32.dart';
import 'package:bip47/src/payment_code.dart';
import 'package:bip47/src/secret_point.dart';
import 'package:bip47/src/util.dart';
import 'package:bitcoindart/bitcoindart.dart' as bitcoindart;
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/pointycastle.dart';

class PaymentAddress {
  final PaymentCode paymentCode;
  final BIP32? bip32Node;
  final bitcoindart.NetworkType networkType;
  int index;

  static final curveParams = ECDomainParameters("secp256k1");

  PaymentAddress({
    required this.paymentCode,
    this.bip32Node,
    bitcoindart.NetworkType? networkType,
    this.index = 0,
  }) : networkType = networkType ?? bitcoindart.bitcoin;

  ECPoint sG() => (curveParams.G * getSecretPoint())!;

  SecretPoint getSharedSecret() => SecretPoint(
        bip32Node!.privateKey!,
        paymentCode.derivePublicKey(index),
      );

  BigInt getSecretPoint() {
    // convert hash to value 's'
    final BigInt s = hashSharedSecret().toBigInt;

    // check that 's' is a member of the associated scalar group
    if (!s.isScalarGroupMemberOf(curveParams)) {
      throw Exception("Secret point is not a member of the secp256k1 group");
    }

    return s;
  }

  ECPoint getECPoint() =>
      curveParams.curve.decodePoint(paymentCode.derivePublicKey(index))!;

  Uint8List hashSharedSecret() =>
      SHA256Digest().process(getSharedSecret().ecdhSecret());

  bitcoindart.ECPair _getSendAddressKeyPair() {
    final sum = getECPoint() + sG();
    return bitcoindart.ECPair.fromPublicKey(
      sum!.getEncoded(true),
      network: networkType,
    );
  }

  String getSendAddressP2PKH() {
    final pair = _getSendAddressKeyPair();

    final p2pkh = bitcoindart.P2PKH(
      data: bitcoindart.PaymentData(pubkey: pair.publicKey),
      network: networkType,
    );

    return p2pkh.data.address!;
  }

  String getSendAddressP2WPKH() {
    final pair = _getSendAddressKeyPair();

    final p2pkh = bitcoindart.P2WPKH(
      data: bitcoindart.PaymentData(pubkey: pair.publicKey),
      network: networkType,
    );

    return p2pkh.data.address!;
  }

  bitcoindart.ECPair _getReceiveAddressKeyPair() {
    final pair = bitcoindart.ECPair.fromPrivateKey(
      _addSecp256k1(
        bip32Node!.privateKey!.toBigInt,
        getSecretPoint(),
      ).toBytes,
      network: networkType,
    );
    return pair;
  }

  String getReceiveAddressP2PKH() {
    final pair = _getReceiveAddressKeyPair();

    final p2pkh = bitcoindart.P2PKH(
      data: bitcoindart.PaymentData(pubkey: pair.publicKey),
      network: networkType,
    );

    return p2pkh.data.address!;
  }

  String getReceiveAddressP2WPKH() {
    final pair = _getReceiveAddressKeyPair();

    final p2pkh = bitcoindart.P2WPKH(
      data: bitcoindart.PaymentData(pubkey: pair.publicKey),
      network: networkType,
    );

    return p2pkh.data.address!;
  }

  BigInt _addSecp256k1(BigInt b1, BigInt b2) {
    final BigInt value = b1 + b2;

    return value % curveParams.n;
  }
}
