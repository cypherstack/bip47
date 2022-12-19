import 'dart:typed_data';

import 'package:bip32/bip32.dart';
import 'package:bip47/src/payment_code.dart';
import 'package:bip47/src/secret_point.dart';
import 'package:bip47/src/util.dart';
import 'package:bitcoindart/bitcoindart.dart' as bitcoindart;
import 'package:cryptography/cryptography.dart';
import 'package:pointycastle/pointycastle.dart';

final bitcoin_ = NetworkType(
  bip32: Bip32Type(
      public: bitcoindart.bitcoin.bip32.public,
      private: bitcoindart.bitcoin.bip32.private),
  wif: bitcoindart.bitcoin.wif,
);

class PaymentAddress {
  late PaymentCode paymentCode;
  NetworkType? networkType;
  late int index;
  Uint8List? privKey;

  static final curveParams = ECDomainParameters("secp256k1");

  void init(PaymentCode paymentCode, [NetworkType? networkType]) {
    this.paymentCode = paymentCode;
    this.networkType = networkType ?? bitcoin_;
    index = 0;
  }

  void initWith(
    Uint8List privKey,
    PaymentCode paymentCode,
    int index, [
    NetworkType? networkType,
  ]) {
    this.privKey = privKey;
    this.paymentCode = paymentCode;
    this.index = index;
    this.networkType = networkType ?? bitcoin_;
  }

  Future<ECPoint> get_sG() async {
    final s = await getSecretPoint();
    return _get_sG(s!);
  }

  SecretPoint getSharedSecret() {
    return _sharedSecret();
  }

  Future<BigInt?> getSecretPoint() {
    return _secretPoint();
  }

  ECPoint getECPoint() {
    final point =
        curveParams.curve.decodePoint(paymentCode.derivePublicKey(index));
    return point!;
  }

  Future<Uint8List> hashSharedSecret() async {
    final hash = await Sha256().hash(getSharedSecret().ecdhSecret());
    return Uint8List.fromList(hash.bytes);
  }

  ECPoint _get_sG(BigInt s) {
    return (curveParams.G * s)!;
  }

  Future<String> getSendAddress() async {
    final s = await getSecretPoint();
    ECPoint ecPoint = getECPoint();
    ECPoint sG = _get_sG(s!);
    final sum = ecPoint + sG;
    final pair = bitcoindart.ECPair.fromPublicKey(sum!.getEncoded(true));

    final p2pkh = bitcoindart.P2PKH(
        data: bitcoindart.PaymentData(pubkey: pair.publicKey));

    return p2pkh.data.address!;
  }

  Future<String> getReceiveAddress() async {
    final s = await getSecretPoint();
    BigInt privKeyValue = Util.bytesToInt(
        bitcoindart.ECPair.fromPrivateKey(privKey!).privateKey!);
    bitcoindart.ECPair pair = bitcoindart.ECPair.fromPrivateKey(
        Util.intToBytes(_addSecp256k1(privKeyValue, s!)));

    final p2pkh = bitcoindart.P2PKH(
        data: bitcoindart.PaymentData(pubkey: pair.publicKey));

    return p2pkh.data.address!;
  }

  BigInt _addSecp256k1(BigInt b1, BigInt b2) {
    BigInt ret = b1 + b2;

    if (ret.bitLength > curveParams.n.bitLength) {
      return ret % curveParams.n;
    }

    return ret;
  }

  SecretPoint _sharedSecret() {
    return SecretPoint(privKey!, paymentCode.derivePublicKey(index));
  }

  bool _isSecp256k1(BigInt b) {
    if (b.compareTo(BigInt.one) <= 0 || b.bitLength > curveParams.n.bitLength) {
      return false;
    }

    return true;
  }

  Future<BigInt?> _secretPoint() async {
    //
    // convert hash to value 's'
    //
    BigInt s = Util.bytesToInt(await hashSharedSecret());
    //
    // check that 's' is on the secp256k1 curve
    //
    if (!_isSecp256k1(s)) {
      print("Secret point not on secp256k1 curve");
      return null;
    }

    return s;
  }
}
