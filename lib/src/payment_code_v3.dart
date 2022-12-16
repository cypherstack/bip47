import 'dart:typed_data';

import 'package:bip32/bip32.dart';
import 'package:bip47/src/secret_point.dart';
import 'package:bip47/src/util.dart';
import 'package:bitcoindart/bitcoindart.dart' as bitcoindart;
import 'package:cryptography/cryptography.dart';

class PaymentCodeV3 {
  static const int MAGIC_VALUE = 0x22;
  static const int VERSION_3 = 0x03;

  static const int BLIND_LEN = 32;
  static const int CHECKSUM_LEN = 4;
  static const int PAYLOAD_LEN = 35;
  static const int PRIVLEY_LEN = 32;
  static const int PUBKEY_LEN = 33;

  String? _strPaymentCode;
  Uint8List _payload = Uint8List(PAYLOAD_LEN);
  String? _xprv;

  Future<void> initFromXPubStr(String xPubStr) async {
    final payload = payloadFrom(xPubStr)!;
    Util.copyBytes(payload, 0, _payload, 0, _payload.length);
    _strPaymentCode = await serialize(payload);
  }

  Future<void> initFromPayload(Uint8List payload) async {
    Util.copyBytes(payload, 0, _payload, 0, _payload.length);
    _strPaymentCode = await serialize(payload);
  }

  void setXprv(String xprvstr) {
    try {
      Util.decodeBase58Check(xprvstr);
      _xprv = xprvstr;
    } catch (_) {
      _xprv = null;
    }
  }

  bool hasPrivate() {
    return _xprv != null;
  }

  @override
  String toString() {
    return _strPaymentCode ?? "null";
  }

  Uint8List getPubkey() {
    Uint8List pubkey = Uint8List(PUBKEY_LEN);
    Uint8List payload = Util.decodeBase58(_strPaymentCode!);
    Util.copyBytes(payload, 2, pubkey, 0, pubkey.length);
    return pubkey;
  }

  Future<Uint8List> getChainCode() async {
    final sha = Sha256();
    final hash = await sha.hash(getPubkey());
    Uint8List ret = Uint8List.fromList(hash.bytes);
    return ret;
  }

  Uint8List getPayload() {
    Uint8List pcBytes = Util.decodeBase58Check(_strPaymentCode!);

    Uint8List payload = Uint8List(pcBytes.length - 1);
    Util.copyBytes(pcBytes, 1, payload, 0, payload.length);

    return payload;
  }

  Future<Uint8List?> getNotifPubkey() {
    return derivePubkey(0);
  }

  Future<Uint8List?> derivePubkey(int index) async {
    Uint8List pubkey = getPubkey();
    Uint8List chainCode = await getChainCode();

    final node = BIP32.fromPublicKey(pubkey, chainCode);
    return node.derive(index).publicKey;
  }

  Future<Uint8List?> getNotifPrivkey() {
    return derivePrivkey(0);
  }

  Future<Uint8List?> derivePrivkey(int index) async {
    if (!hasPrivate()) {
      return null;
    }

    Uint8List chainCode = await getChainCode();

    Uint8List xprivbuf = Util.decodeBase58Check(_xprv!);
    Uint8List privkey = Uint8List(PRIVLEY_LEN);
    Util.copyBytes(xprivbuf, xprivbuf.length - 32, privkey, 0, privkey.length);

    final node = BIP32.fromPrivateKey(
      privkey,
      chainCode,
    );
    return node.privateKey;
  }

  Future<Uint8List> getIdentifierV1() {
    return getIdentifier(Uint8List.fromList([0x01]));
  }

  Future<Uint8List> getIdentifierV2() {
    return getIdentifier(Uint8List.fromList([0x02]));
  }

  Future<Uint8List> getIdentifierV3() {
    return getIdentifier(Uint8List.fromList([0x03]));
  }

  Future<Uint8List> blind(
      bitcoindart.ECPair eckey, PaymentCodeV3 oPcode) async {
    SecretPoint secretPoint =
        SecretPoint(eckey.privateKey!, (await oPcode.getNotifPubkey())!);
    Uint8List secretPointX = secretPoint.ecdhSecret();
    Uint8List blindFactor = Util.getSha512HMAC(secretPointX, eckey.publicKey);
    Uint8List G = Uint8List(PUBKEY_LEN);
    G[0] = getPayload()[1];
    Uint8List bf = Uint8List(BLIND_LEN);
    Uint8List pc = Uint8List(BLIND_LEN);
    Util.copyBytes(blindFactor, 0, bf, 0, bf.length);
    Uint8List pl = getPayload();
    Util.copyBytes(pl, 2, pc, 0, pc.length);
    Util.copyBytes(Util.xor(bf, pc)!, 0, G, 1, Util.xor(bf, pc)!.length);

    return G;
  }

  Future<Uint8List?> unblind(Uint8List A, Uint8List G) async {
    if (!hasPrivate()) {
      return null;
    }

    SecretPoint secretPoint = SecretPoint((await getNotifPrivkey())!, A);
    Uint8List secretPointX = secretPoint.ecdhSecret();
    Uint8List blindFactor = Util.getSha512HMAC(secretPointX, A);
    Uint8List bf = Uint8List(BLIND_LEN);
    Util.copyBytes(blindFactor, 0, bf, 0, bf.length);
    Uint8List pl = Uint8List(PAYLOAD_LEN);
    Uint8List pc = Uint8List(BLIND_LEN);
    Util.copyBytes(G, 1, pc, 0, pc.length);
    pl[0] = MAGIC_VALUE;
    pl[1] = VERSION_3;
    pl[2] = G[0];
    Util.copyBytes(Util.xor(bf, pc)!, 0, pl, 3, Util.xor(bf, pc)!.length);

    return pl;
  }

  Future<Uint8List> getIdentifier(Uint8List ver) async {
    Uint8List ret = Uint8List(PUBKEY_LEN);
    ret[0] = 0x02;
    final data = Util.getSha512HMAC(await getChainCode(), ver);
    Util.copyBytes(data, 0, ret, 1, ret.length - 1);
    return ret;
  }

  Uint8List? payloadFrom(String xPubStr) {
    Uint8List? decoded;
    Uint8List? payload = Uint8List(PAYLOAD_LEN);
    try {
      decoded = Util.decodeBase58Check(xPubStr);
    } catch (_) {
      payload = null;
      return null;
    }
    payload[0] = MAGIC_VALUE;
    payload[1] = VERSION_3;

    Util.copyBytes(decoded, decoded.length - 33, payload, 2, PUBKEY_LEN);

    return payload;
  }

  Future<String> serialize(Uint8List payload) async {
    final sha256 = Sha256();
    final first = await sha256.hash(payload);
    final second = await sha256.hash(first.bytes);
    Uint8List checksum = Uint8List(CHECKSUM_LEN);
    for (int i = 0; i < CHECKSUM_LEN; i++) {
      checksum[i] = second.bytes[i];
    }

    Uint8List paymentCodeChecksum = Uint8List(payload.length + checksum.length);
    Util.copyBytes(payload, 0, paymentCodeChecksum, 0, payload.length);
    Util.copyBytes(checksum, 0, paymentCodeChecksum,
        paymentCodeChecksum.length - CHECKSUM_LEN, checksum.length);

    return Util.encodeBase58(paymentCodeChecksum);
  }
}
