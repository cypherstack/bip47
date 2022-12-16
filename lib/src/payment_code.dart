import 'dart:typed_data';

import 'package:bip32/bip32.dart';
import 'package:bip47/src/util.dart';
import 'package:bitcoindart/bitcoindart.dart' as bitcoindart;
import 'package:cryptography/cryptography.dart';

class PaymentCode {
  static const int PUBLIC_KEY_Y_OFFSET = 2;
  static const int PUBLIC_KEY_X_OFFSET = 3;
  static const int CHAIN_OFFSET = 35;
  static const int PUBLIC_KEY_X_LEN = 32;
  static const int PUBLIC_KEY_Y_LEN = 1;
  static const int CHAIN_LEN = 32;
  static const int PAYLOAD_LEN = 80;
  static const int CHECKSUM_LEN = 4;

  String? _paymentCodeString;
  Uint8List? _publicKey;
  Uint8List? _chainCode;
  NetworkType? networkType;

  PaymentCode();

  PaymentCode.fromPaymentCode(this._paymentCodeString, this.networkType) {
    final parsed = _parse();
    _publicKey = parsed[0];
    _chainCode = parsed[1];
  }

  Future<void> initFromPayload(Uint8List payload) async {
    if (payload.length != 80) {
      return;
    }

    _publicKey = Uint8List(PUBLIC_KEY_Y_LEN + PUBLIC_KEY_X_LEN);
    _chainCode = Uint8List(CHAIN_LEN);

    Util.copyBytes(payload, PUBLIC_KEY_Y_OFFSET, _publicKey!, 0,
        PUBLIC_KEY_Y_LEN + PUBLIC_KEY_X_LEN);
    Util.copyBytes(payload, CHAIN_OFFSET, _chainCode!, 0, CHAIN_LEN);

    _paymentCodeString = await _makeV1();
  }

  Future<void> initFromPubKey(
    Uint8List publicKey,
    Uint8List chain, [
    NetworkType? networkType,
  ]) async {
    _publicKey = publicKey;
    _chainCode = chain;
    this.networkType = networkType;
    _paymentCodeString = await _makeV1();
  }

  String notificationAddress() {
    return addressAt(0);
  }

  String addressAt(int index) {
    final publicKey = derivePublicKey(index);
    final p2p = bitcoindart.P2PKH(
      data: bitcoindart.PaymentData(pubkey: publicKey),
      network: networkType,
    );
    return p2p.data.address!;
  }

  Uint8List derivePublicKey(int index) {
    final node = BIP32.fromPublicKey(_publicKey!, _chainCode!, networkType);
    return node.derive(index).publicKey;
  }

  Uint8List getPayload() {
    Uint8List pcBytes = Util.decodeBase58Check(_paymentCodeString!);

    Uint8List payload = Uint8List(PAYLOAD_LEN);
    Util.copyBytes(pcBytes, 1, payload, 0, payload.length);

    return payload;
  }

  int getType() {
    Uint8List payload = getPayload();
    return payload.first;
  }

  Uint8List getPubKey() {
    return _publicKey!;
  }

  Uint8List getChain() {
    return _chainCode!;
  }

  @override
  String toString() {
    return _paymentCodeString ?? "";
  }

  static Uint8List getMask(Uint8List sPoint, Uint8List oPoint) {
    return Util.getSha512HMAC(oPoint, sPoint);
  }

  static Uint8List blind(Uint8List payload, Uint8List mask) {
    Uint8List ret = Uint8List(PAYLOAD_LEN);
    Uint8List pubkey = Uint8List(PUBLIC_KEY_X_LEN);
    Uint8List chain = Uint8List(CHAIN_LEN);
    Uint8List buf0 = Uint8List(PUBLIC_KEY_X_LEN);
    Uint8List buf1 = Uint8List(CHAIN_LEN);

    Util.copyBytes(payload, 0, ret, 0, PAYLOAD_LEN);

    Util.copyBytes(payload, PUBLIC_KEY_X_OFFSET, pubkey, 0, PUBLIC_KEY_X_LEN);
    Util.copyBytes(payload, CHAIN_OFFSET, chain, 0, CHAIN_LEN);
    Util.copyBytes(mask, 0, buf0, 0, PUBLIC_KEY_X_LEN);
    Util.copyBytes(mask, PUBLIC_KEY_X_LEN, buf1, 0, CHAIN_LEN);

    Util.copyBytes(
        Util.xor(pubkey, buf0)!, 0, ret, PUBLIC_KEY_X_OFFSET, PUBLIC_KEY_X_LEN);
    Util.copyBytes(Util.xor(chain, buf1)!, 0, ret, CHAIN_OFFSET, CHAIN_LEN);

    return ret;
  }

  List<Uint8List> _parse() {
    Uint8List pcBytes = Util.decodeBase58Check(_paymentCodeString!);

    if (pcBytes[0] != 0x47) {
      throw Exception("invalid payment code version");
    }

    Uint8List chain = Uint8List(CHAIN_LEN);
    Uint8List pub = Uint8List(PUBLIC_KEY_X_LEN + PUBLIC_KEY_Y_LEN);

    Util.copyBytes(pcBytes, 3, pub, 0, pub.length);
    Util.copyBytes(pcBytes, 3 + pub.length, chain, 0, chain.length);

    return [pub, chain];
  }

  Future<String> _makeV1() async {
    Uint8List payload = Uint8List(PAYLOAD_LEN);
    Uint8List paymentCode = Uint8List(PAYLOAD_LEN + 1);

    for (int i = 0; i < payload.length; i++) {
      payload[i] = 0x00;
    }

    // byte 0: type. required value: 0x01
    payload[0] = 0x01;
    // byte 1: features bit field. All bits must be zero except where specified elsewhere in this specification
    //      bit 0: Bitmessage notification
    //      bits 1-7: reserved
    payload[1] = 0x00;

    // replace sign & x code (33 bytes)
    Util.copyBytes(
        _publicKey!, 0, payload, PUBLIC_KEY_Y_OFFSET, _publicKey!.length);
    // replace chain code (32 bytes)
    Util.copyBytes(_chainCode!, 0, payload, CHAIN_OFFSET, _chainCode!.length);

    // add version byte
    paymentCode[0] = 0x47;
    Util.copyBytes(payload, 0, paymentCode, 1, payload.length);

    // append checksum
    final sha256 = Sha256();
    final first = await sha256.hash(paymentCode);
    final second = await sha256.hash(first.bytes);
    Uint8List checksum = Uint8List(CHECKSUM_LEN);
    for (int i = 0; i < CHECKSUM_LEN; i++) {
      checksum[i] = second.bytes[i];
    }
    Uint8List paymentCodeChecksum =
        Uint8List(paymentCode.length + checksum.length);
    Util.copyBytes(paymentCode, 0, paymentCodeChecksum, 0, paymentCode.length);
    Util.copyBytes(checksum, 0, paymentCodeChecksum,
        paymentCodeChecksum.length - CHECKSUM_LEN, checksum.length);

    return Util.encodeBase58(paymentCodeChecksum);
  }

//  DeterministicKey createMasterPubKeyFromBytes(Uint8List pub, Uint8List chain)   {
// return HDKeyDerivation.createMasterPubKeyFromBytes(pub, chain);
// }

  bool isValid() {
    try {
      Uint8List pcodeBytes = Util.decodeBase58Check(_paymentCodeString!);

      if (pcodeBytes[0] != 0x47) {
        throw Exception("invalid version: $_paymentCodeString");
      } else {
        int firstByte = pcodeBytes[3];
        if (firstByte == 0x02 || firstByte == 0x03) {
          return true;
        } else {
          return false;
        }
      }
    } catch (e) {
      return false;
    }
  }
}
